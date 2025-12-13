package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"netflow-reporter/pkg"
	"os/signal"
	"syscall"
	"time"
)

func main() {
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
			batch_size := 100_000 + time.Now().UnixNano()%1_000_000

			batch := make([]pkg.NetflowPacket, 0, batch_size)
			for range batch_size {
				batch = append(batch, pkg.NetflowPacket{
					IP:        pkg.GetRandIP(),
					Protocol:  pkg.GetRandProtocol(),
					ISP:       pkg.GetRandISP(),
					Country:   pkg.GetRandCountry(),
					Direction: pkg.GetRandDirection(),
					ByteSum:   time.Now().UnixNano() % 100_000,
				})
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
			time.Sleep(time.Millisecond * 500)
		}
	}()
	<-ctx.Done()
}
