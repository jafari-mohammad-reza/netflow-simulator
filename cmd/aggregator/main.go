package main

import (
	"context"
	"netflow-reporter/internal"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()
	// start listener for queing the flow
	// process flow each 15 seconds
	queue := &internal.ConnFlowQueue{}
	if err := queue.Start(ctx); err != nil {
		panic(err)
	}
	<-ctx.Done()
}
