package main

import (
	"context"
	crand "crypto/rand"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"path/filepath"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/topology"

	"example.com/scion-time/go/core"
	"example.com/scion-time/go/drivers"
)

const (
	flagStartRound = 0
	flagBroadcast  = 1
	flagUpdate     = 2

	roundPeriod   = 5 * time.Second
	roundDuration = 2 * time.Second
)

type tsConfig struct {
	MBGTimeSources []string `toml:"mbg_time_sources,omitempty"`
	NTPTimeSources []string `toml:"ntp_time_sources,omitempty"`
}

type timeSource interface {
	fetchTime() (refTime time.Time, sysTime time.Time, err error)
}

type mbgTimeSource string
type ntpTimeSource string

type timeInfo struct {
	refTime time.Time
	sysTime time.Time
}

func (ti timeInfo) clockOffset() time.Duration {
	return ti.refTime.Sub(ti.sysTime)
}

type syncEntry struct {
	ia        addr.IA
	syncInfos []core.SyncInfo
}

var timeSources []timeSource

func newSciondConnector(addr string, ctx context.Context) daemon.Connector {
	c, err := daemon.NewService(addr).Connect(ctx)
	if err != nil {
		log.Fatal("Failed to create SCION connector:", err)
	}
	return c
}

func newPacketDispatcher(c daemon.Connector) snet.PacketDispatcherService {
	return &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: c},
		},
	}
}

func medianClockOffset(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool {
		return ds[i] < ds[j]
	})
	var m time.Duration
	n := len(ds)
	if n == 0 {
		m = 0
	} else {
		i := n / 2
		if n%2 != 0 {
			m = ds[i]
		} else {
			m = (ds[i] + ds[i-1]) / 2
		}
	}
	return m
}

func medianTimeInfo(tis []timeInfo) timeInfo {
	sort.Slice(tis, func(i, j int) bool {
		return tis[i].clockOffset() < tis[j].clockOffset()
	})
	var m timeInfo
	n := len(tis)
	if n == 0 {
		m = timeInfo{}
	} else {
		i := n / 2
		if n%2 != 0 {
			m = tis[i]
		} else {
			b := make([]byte, 1)
			_, err  := crand.Read(b)
			if err != nil {
				log.Printf("Failed to read random number: %v", err)
			}
			if b[0] > 127 {
				m = tis[i]
			} else {
				m = tis[i-1]
			}
		}
	}
	return m
}

func midpoint(ds []time.Duration, f int) time.Duration {
	sort.Slice(ds, func(i, j int) bool {
		return ds[i] < ds[j]
	})
	return (ds[f] + ds[len(ds)-1-f]) / 2
}

func (s mbgTimeSource) fetchTime() (time.Time, time.Time, error) {
	return drivers.FetchMBGTime(string(s))
}

func (s ntpTimeSource) fetchTime() (time.Time, time.Time, error) {
	return drivers.FetchNTPTime(string(s))
}

func fetchTime() <-chan timeInfo {
	ti := make(chan timeInfo, 1)
	go func() {
		var tis []timeInfo
		ch := make(chan timeInfo)
		for _, h := range timeSources {
			go func(s timeSource) {
				refTime, sysTime, err := s.fetchTime()
				if err != nil {
					log.Printf("Failed to fetch clock offset from %v: %v", s, err)
					ch <- timeInfo{}
					return
				}
				ch <- timeInfo{refTime: refTime, sysTime: sysTime}
			}(h)
		}
		for i := 0; i != len(timeSources); i++ {
			x := <-ch
			if !x.refTime.IsZero() || !x.sysTime.IsZero() {
				tis = append(tis, x)
			}
		}
		m := medianTimeInfo(tis)
		log.Printf("Fetched local time info: refTime: %v, sysTime: %v", m.refTime, m.sysTime)
		ti <- m
	}()
	return ti
}

func syncEntryClockOffset(syncInfos []core.SyncInfo) time.Duration {
	var clockOffsets []time.Duration
	for _, syncInfo := range syncInfos {
		clockOffsets = append(clockOffsets, syncInfo.ClockOffset)
	}
	return medianClockOffset(clockOffsets)
}

func syncEntryForIA(syncEntries []syncEntry, ia addr.IA) *syncEntry {
	for i, x := range syncEntries {
		if x.ia == ia {
			return &syncEntries[i]
		}
	}
	return nil
}

func syncInfoForHost(syncInfos []core.SyncInfo, host addr.HostAddr) *core.SyncInfo {
	for i, x := range syncInfos {
		if x.Source.Host.Equal(host) {
			return &syncInfos[i]
		}
	}
	return nil
}

func newTimer() *time.Timer {
	t := time.NewTimer(0)
	<-t.C
	return t
}

func scheduleNextRound(t *time.Timer, syncTime *time.Time) {
	now := time.Now().UTC()
	*syncTime = now.Add(roundPeriod).Truncate(roundPeriod)
	t.Reset(syncTime.Add(-(roundDuration / 2)).Sub(now))
}

func scheduleBroadcast(t *time.Timer, syncTime time.Time) {
	now := time.Now().UTC()
	t.Reset(syncTime.Sub(now))
}

func scheduleUpdate(t *time.Timer, syncTime time.Time) {
	now := time.Now().UTC()
	t.Reset(syncTime.Add(roundDuration / 2).Sub(now))
}

func main() {
	var sciondAddr string
	var localAddr snet.UDPAddr
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")
	flag.Var(&localAddr, "local", "Local address")
	flag.Parse()

	var err error
	ctx := context.Background()

	var cfg tsConfig
	cfgFile := filepath.Join(".", "gen",
		fmt.Sprintf("AS%s/ts.toml", localAddr.IA.A.FileFmt()))
	if err := config.LoadFile(cfgFile, &cfg); err != nil {
		log.Fatal("Failed to load configuration:", err)
	}
	for _, s := range cfg.MBGTimeSources {
		timeSources = append(timeSources, mbgTimeSource(s))
	}
	for _, s := range cfg.NTPTimeSources {
		timeSources = append(timeSources, ntpTimeSource(s))
	}

	topoFile := filepath.Join(".", "gen",
		fmt.Sprintf("AS%s/topology.json", localAddr.IA.A.FileFmt()))
	topo, err := topology.FromJSONFile(topoFile)
	if err != nil {
		log.Fatal("Failed to load topology:", err)
	}
	tsInfos, err := topo.TimeServices()
	if err != nil {
		log.Fatal("Failed to load local time service infos:", err)
	}
	var peers []addr.IA
	for _, tsi := range tsInfos {
		a := tsi.Addr.SCIONAddress
		if a.IP.Equal(localAddr.Host.IP) &&
			a.Port == localAddr.Host.Port &&
			a.Zone == localAddr.Host.Zone {
			peers = tsi.Peers
		}
	}

	pathInfos, err := core.StartPather(newSciondConnector(sciondAddr, ctx), ctx, peers)
	if err != nil {
		log.Fatal("Failed to start TSP pather:", err)
	}
	var pathInfo core.PathInfo

	syncInfos, err := core.StartHandler(
		newPacketDispatcher(newSciondConnector(sciondAddr, ctx)), ctx,
		localAddr.IA, localAddr.Host)
	if err != nil {
		log.Fatal("Failed to start TSP handler:", err)
	}

	localAddr.Host.Port = 0
	err = core.StartPropagator(
		newPacketDispatcher(newSciondConnector(sciondAddr, ctx)), ctx,
		localAddr.IA, localAddr.Host)
	if err != nil {
		log.Fatal("Failed to start TSP propagator:", err)
	}

	var localTimeInfo struct {
		i timeInfo
		c <-chan timeInfo
	}

	var syncEntries []syncEntry
	var syncTime time.Time

	flag := flagStartRound
	syncTimer := newTimer()
	scheduleNextRound(syncTimer, &syncTime)

	for {
		select {
		case pathInfo = <-pathInfos:
			log.Printf("Received new path info.")
		case syncInfo := <-syncInfos:
			log.Printf("Received new sync info: %v", syncInfo)
			se := syncEntryForIA(syncEntries, syncInfo.Source.IA)
			if se == nil {
				syncEntries = append(syncEntries, syncEntry{
					ia: syncInfo.Source.IA,
				})
				se = &syncEntries[len(syncEntries)-1]
			}
			si := syncInfoForHost(se.syncInfos, syncInfo.Source.Host)
			if si != nil {
				*si = syncInfo
			} else {
				se.syncInfos = append(se.syncInfos, syncInfo)
			}
		case now := <-syncTimer.C:
			now = now.UTC()
			log.Printf("Received new timer signal: %v", now)
			switch flag {
			case flagStartRound:
				log.Printf("START ROUND")

				syncEntries = nil
				localTimeInfo.i = timeInfo{}
				localTimeInfo.c = fetchTime()

				flag = flagBroadcast
				scheduleBroadcast(syncTimer, syncTime)
			case flagBroadcast:
				log.Printf("BROADCAST\")

				if len(localTimeInfo.c) == 0 {
					scheduleNextRound(syncTimer, &syncTime)
				} else {
					localTimeInfo.i = <-localTimeInfo.c

					for remoteIA, ps := range pathInfo.PeerASes {
						if syncEntryForIA(syncEntries, remoteIA) == nil {
							syncEntries = append(syncEntries, syncEntry{
								ia: remoteIA,
							})
						}
						if len(ps) != 0 {
							sp := ps[mrand.Intn(len(ps))]
							core.PropagatePacketTo(
								&snet.Packet{
									PacketInfo: snet.PacketInfo{
										Destination: snet.SCIONAddress{
											IA:   remoteIA,
											Host: addr.SvcTS | addr.SVCMcast,
										},
										Path: sp.Path(),
										Payload: snet.UDPPayload{
											Payload: []byte(localTimeInfo.i.clockOffset().String()),
										},
									},
								},
								sp.UnderlayNextHop())
						}
					}

					localSyncInfo := core.SyncInfo{
						Source: snet.SCIONAddress{
							IA:   localAddr.IA,
							Host: addr.HostFromIP(localAddr.Host.IP),
						},
						ClockOffset: localTimeInfo.i.clockOffset(),
					}
					se := syncEntryForIA(syncEntries, localAddr.IA)
					if se == nil {
						syncEntries = append(syncEntries, syncEntry{
							ia: localAddr.IA,
						})
						se = &syncEntries[len(syncEntries)-1]
					}
					si := syncInfoForHost(se.syncInfos, addr.HostFromIP(localAddr.Host.IP))
					if si != nil {
						*si = localSyncInfo
					} else {
						se.syncInfos = append(se.syncInfos, localSyncInfo)
					}

					flag = flagUpdate
					scheduleUpdate(syncTimer, syncTime)
				}
			case flagUpdate:
				log.Printf("UPDATE")

				var clockOffsets []time.Duration
				for _, se := range syncEntries {
					var d time.Duration
					if len(se.syncInfos) != 0 {
						d = syncEntryClockOffset(se.syncInfos)
					} else {
						d = localTimeInfo.i.clockOffset()
					}
					clockOffsets = append(clockOffsets, d)
					log.Printf("\t%v:", se.ia)
					for _, si := range se.syncInfos {
						log.Printf("\t\t%v", si)
					}
				}

				loff := localTimeInfo.i.clockOffset()
				lref := localTimeInfo.i.refTime

				goff := loff
				if len(clockOffsets) != 0 {
					f := (len(clockOffsets) - 1) / 3
					goff = midpoint(clockOffsets, f)
				}
				gref := lref.Add(loff - goff)

				log.Printf("refTime: %v, sysTime: %v", gref , localTimeInfo.i.sysTime)

				drivers.StoreSHMClockSample(gref, localTimeInfo.i.sysTime)

				flag = flagStartRound
				scheduleNextRound(syncTimer, &syncTime)
			}
		}
	}
}
