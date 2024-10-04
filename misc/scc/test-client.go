package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"

	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	sgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/segment/segfetcher"
	"github.com/scionproto/scion/private/segment/segfetcher/grpc"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

type nextHopper struct {
	topo *topology.Loader
}

func (h nextHopper) UnderlayNextHop(ifID uint16) *net.UDPAddr {
	return h.topo.UnderlayNextHop(ifID)
}

type localInfo struct{}

func (localInfo) IsSegLocal(_ segfetcher.Request) bool {
	return false
}

type segVerifier struct{}

func (segVerifier) Verify(
	_ context.Context, _ *crypto.SignedMessage, _ ...[]byte) (*signed.Message, error) {
	return nil, nil
}

func (v segVerifier) WithServer(net.Addr) verifier.Verifier {
	return v
}

func (v segVerifier) WithIA(addr.IA) verifier.Verifier {
	return v
}

func (v segVerifier) WithValidity(cppki.Validity) verifier.Verifier {
	return v
}

type dstProvider struct{}

func (dstProvider) Dst(_ context.Context, _ segfetcher.Request) (net.Addr, error) {
	return &snet.SVCAddr{SVC: addr.SvcCS}, nil
}

func main() {
	var localAddr snet.UDPAddr
	var remoteAddr snet.UDPAddr
	var data string
	flag.Var(&localAddr, "local", "Local address")
	flag.Var(&remoteAddr, "remote", "Remote address")
	flag.StringVar(&data, "data", "", "Data")
	flag.Parse()

	ctx := context.Background()

	topo, err := topology.NewLoader(topology.LoaderCfg{
		File: "./topology.json",
	})
	if err != nil {
		log.Fatalf("Failed to create topology loader: %v", err)
	}
	go func() {
		err = topo.Run(ctx)
		if err != nil {
			log.Fatalf("Failed to load topology: %v", err)
		}
	}()

	dialer := &sgrpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("unexpected address type")
			}
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}
	rpc := &grpc.Requester{
		Dialer: dialer,
	}
	pathDB, err := storage.NewPathStorage(storage.DBConfig{
		Connection: "./path.db",
	})
	if err != nil {
		log.Fatalf("Failed to create path DB: %v", err)
	}
	trustDB, err := storage.NewTrustStorage(storage.DBConfig{
		Connection: "./trust.db",
	})
	if err != nil {
		log.Fatalf("Failed to create trust DB: %v", err)
	}
	_, err = trust.LoadTRCs(ctx, "./certs", trustDB)
	if err != nil {
		log.Fatalf("Failed to load TRCs: %v", err)
	}
	revCache := storage.NewRevocationStorage()

	pather := segfetcher.Pather{
		IA:  topo.IA(),
		MTU: topo.MTU(),
		NextHopper: nextHopper{
			topo: topo,
		},
		RevCache: revCache,
		Fetcher: &segfetcher.Fetcher{
			PathDB: pathDB,
			Resolver: segfetcher.NewResolver(
				pathDB,
				revCache,
				localInfo{},
			),
			ReplyHandler: &seghandler.Handler{
				Verifier: &seghandler.DefaultVerifier{
					Verifier: segVerifier{},
				},
				Storage: &seghandler.DefaultStorage{
					PathDB:   pathDB,
					RevCache: revCache,
				},
			},
			Requester: &segfetcher.DefaultRequester{
				RPC:         rpc,
				DstProvider: dstProvider{},
			},
			Metrics: segfetcher.NewFetcherMetrics("sd"),
		},
		Splitter: &segfetcher.MultiSegmentSplitter{
			LocalIA: topo.IA(),
			Core:    topo.Core(),
			Inspector: trust.DBInspector{
				DB: trustDB,
			},
		},
	}

	ps, err := pather.GetPaths(ctx, remoteAddr.IA, true /* refresh*/)
	if err != nil {
		log.Fatalf("Failed to lookup paths: %v", err)
	}

	if len(ps) == 0 {
		log.Fatalf("No paths to %v available", remoteAddr.IA)
	}

	log.Printf("Available paths to %v:", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("\t%v\n", p)
	}

	sp := ps[0]

	log.Printf("Selected path to %v:\n", remoteAddr.IA)
	log.Printf("\t%v\n", sp)

	conn, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		log.Fatalf("Failed to bind UDP connection: %v", err)
	}
	defer conn.Close()

	srcAddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		log.Fatal("Unexpected address type")
	}
	srcAddr = srcAddr.Unmap()
	dstAddr, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		log.Fatal("Unexpected address type")
	}
	dstAddr = dstAddr.Unmap()

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localAddr.IA,
				Host: addr.HostIP(srcAddr),
			},
			Destination: snet.SCIONAddress{
				IA:   remoteAddr.IA,
				Host: addr.HostIP(dstAddr),
			},
			Path: sp.Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: uint16(localAddr.Host.Port),
				DstPort: uint16(remoteAddr.Host.Port),
				Payload: []byte(data),
			},
		},
	}

	nextHop := sp.UnderlayNextHop()
	if nextHop == nil && remoteAddr.IA.Equal(localAddr.IA) {
		nextHop = remoteAddr.Host
	}

	err = pkt.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize SCION packet: %v", err)
	}

	_, err = conn.WriteTo(pkt.Bytes, nextHop)
	if err != nil {
		log.Fatalf("Failed to write packet: %v", err)
	}

	pkt.Prepare()
	n, _, err := conn.ReadFrom(pkt.Bytes)
	if err != nil {
		log.Fatalf("Failed to read packet: %v", err)
	}
	pkt.Bytes = pkt.Bytes[:n]

	err = pkt.Decode()
	if err != nil {
		log.Fatalf("Failed to decode packet: %v", err)
	}

	pld, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		log.Fatal("Failed to read packet payload")
	}

	log.Printf("Received data: \"%s\"", string(pld.Payload))
}
