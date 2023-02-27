package prev

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

const handlerLogPrefix = "[core/prev/handler]"

type SyncInfo struct {
	Source      snet.SCIONAddress
	ClockOffset time.Duration
}

func StartHandler(s snet.PacketDispatcherService, ctx context.Context,
	localIA addr.IA, localHost *net.UDPAddr) (<-chan SyncInfo, error) {
	conn, localPort, err := s.Register(ctx, localIA, localHost, addr.SvcNone /* addr.SvcTS */)
	if err != nil {
		return nil, err
	}

	log.Printf("%s Listening in %v on %v:%d - %v",
		handlerLogPrefix, localIA, localHost.IP, localPort, addr.SvcNone /* addr.SvcTS */)

	syncInfos := make(chan SyncInfo)

	go func() {
		for {
			var packet snet.Packet
			var lastHop net.UDPAddr
			err := conn.ReadFrom(&packet, &lastHop)
			if err != nil {
				log.Printf("%s Failed to read packet: %v", handlerLogPrefix, err)
				continue
			}
			payload, ok := packet.Payload.(snet.UDPPayload)
			if !ok {
				log.Printf("%s Failed to read packet payload: %v", handlerLogPrefix, common.TypeOf(packet.Payload))
				continue
			}

			clockOffset, err := time.ParseDuration(string(payload.Payload))
			if err != nil {
				log.Printf("%s Failed to decode packet: %v", handlerLogPrefix, err)
				continue
			}

			syncInfos <- SyncInfo{
				Source:      packet.Source,
				ClockOffset: clockOffset,
			}
		}
	}()

	return syncInfos, nil
}
