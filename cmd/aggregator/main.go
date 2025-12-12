package main

import (
	"context"
	"fmt"
	"netflow-reporter/internal"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()

	queue := internal.NewConnFlowQueue()

	go func() {
		if err := queue.Start(ctx); err != nil {
			fmt.Println("queue stopped:", err)
		}
	}()

	processor := internal.NewProcessor()
	tk := time.NewTicker(20 * time.Second)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("shutting down...")
			return

		case <-tk.C:
			fmt.Println("processing bucket...")
			go func() {
				bucket := queue.Dequeue()

				if bucket == nil {
					fmt.Printf("no bucket to process\n")
					return
				}
				if len(bucket) == 0 {
					fmt.Printf("empty bucket to process\n")
					return
				}

				if err := processor.ProcessBucket(bucket); err != nil {
					fmt.Printf("failed to process bucket: %s\n", err)
				}
			}()
		}
	}
}
