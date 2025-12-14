package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"netflow-reporter/pkg"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 6070,
	})
	if err != nil {
		log.Fatalf("failed to dial to consumer port 6070: %s", err.Error())
	}
	defer conn.Close()

	go func() {
		for {
			batchSize := 10_000 + rand.Int63n(100_000)

			batch := make([]pkg.NetflowPacket, 0, batchSize)
			for i := int64(0); i < batchSize; i++ {
				var protocol pkg.Protocol
				r := rand.Float64()
				switch {
				case r < 0.60:
					protocol = pkg.ProtocolTCP
				case r < 0.95:
					protocol = pkg.ProtocolUDP
				default:
					protocol = pkg.ProtocolICMP
				}

				packet := pkg.NetflowPacket{
					IP:        pkg.GetRandIP(),
					Protocol:  protocol,
					ISP:       pkg.GetRandISP(),
					Country:   pkg.GetRandCountry(),
					Direction: pkg.GetRandDirection(),
					ByteSum:   rand.Int63n(10_000) + 1,
				}
				batch = append(batch, packet)
			}

			data, err := pkg.MarshalNetflowBatch(batch)
			if err != nil {
				log.Fatalf("failed to marshal netflow batch: %s", err.Error())
			}

			size := int64(len(data))
			if err := binary.Write(conn, binary.BigEndian, size); err != nil {
				log.Fatalf("failed to write netflow batch size to consumer: %s", err.Error())
			}

			if _, err := io.CopyN(conn, bytes.NewReader(data), size); err != nil {
				log.Fatalf("failed to write netflow batch to consumer: %s", err.Error())
			}

			time.Sleep(500 * time.Millisecond)
		}
	}()
	<-ctx.Done()
}
