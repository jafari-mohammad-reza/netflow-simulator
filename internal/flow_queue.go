package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"netflow-reporter/pkg"
	"sync"
	"time"
)

type FlowBucket struct {
	StartedAt int64
	Flow      []pkg.NetflowPacket
}

type ConnFlowQueue struct {
	mu     sync.Mutex
	active *FlowBucket
	queue  []FlowBucket
}

func NewConnFlowQueue() *ConnFlowQueue {
	return &ConnFlowQueue{
		active: &FlowBucket{
			StartedAt: time.Now().Unix(),
			Flow:      make([]pkg.NetflowPacket, 0),
		},
		queue: make([]FlowBucket, 0),
	}
}

func (c *ConnFlowQueue) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", ":6070")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := ln.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept connection: %w", err)
			}
			go c.handleConn(ctx, conn)
		}
	}
}

func (c *ConnFlowQueue) handleConn(ctx context.Context, conn net.Conn) {
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

		c.Enqueue(batch)
	}
}

func (c *ConnFlowQueue) Enqueue(batch []pkg.NetflowPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().Unix()
	if now-c.active.StartedAt > 15 {
		// rotate bucket
		c.queue = append(c.queue, *c.active)

		c.active = &FlowBucket{
			StartedAt: now,
			Flow:      make([]pkg.NetflowPacket, 0),
		}
	}

	c.active.Flow = append(c.active.Flow, batch...)
}

func (c *ConnFlowQueue) Dequeue() []pkg.NetflowPacket {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) == 0 {
		return nil
	}

	bucket := c.queue[0]
	c.queue = c.queue[1:]

	return bucket.Flow
}
