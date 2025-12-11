package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"netflow-reporter/pkg"
)

type ConnFlowQueue struct {
}

func (c *ConnFlowQueue) Start(ctx context.Context) error {
	conn, err := net.Listen("tcp", ":6070")
	if err != nil {
		return fmt.Errorf("failed to open connection in queue: %s", err.Error())
	}
	for {
		select {
		default:
			conn, err := conn.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept new connection: %s", err.Error())
			}
			go func() {
				defer conn.Close()

				for {
					var dataSize int64

					if err := binary.Read(conn, binary.BigEndian, &dataSize); err != nil {
						fmt.Printf("failed to read size: %s\n", err)
						return
					}

					buf := make([]byte, dataSize)
					if _, err := io.ReadFull(conn, buf); err != nil {
						fmt.Printf("failed to read batch: %s\n", err)
						return
					}

					batch, err := pkg.UnmarshalNetflowBatch(buf)
					if err != nil {
						fmt.Printf("failed to unmarshal batch: %s\n", err)
						return
					}

					fmt.Printf("received batch of %d packets\n", len(batch))
				}
			}()

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
