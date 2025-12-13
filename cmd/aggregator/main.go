package main

import (
	"context"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/container/grid"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/tcell"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/mum4k/termdash/widgets/text"

	"netflow-reporter/internal"
)

const maxPoints = 120

type safeStats struct {
	mu       sync.RWMutex
	prev     internal.FlowStats
	prevTime time.Time
	ppsTCP   float64
	ppsUDP   float64
	ppsICMP  float64
	bpsTCP   float64
	bpsUDP   float64
	bpsICMP  float64
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()

	queue := internal.NewConnFlowQueue()
	go queue.Start(ctx)

	processor := internal.NewProcessor()

	go func() {
		tk := time.NewTicker(15 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				bucket := queue.Dequeue()
				if bucket == nil || len(bucket) == 0 {
					continue
				}
				processor.ProcessBucket(bucket)
			}
		}
	}()

	t, err := tcell.New()
	if err != nil {
		panic(err)
	}
	defer t.Close()

	lcPackets, err := linechart.New(
		linechart.AxesCellOpts(cell.FgColor(cell.ColorWhite)),
		linechart.YAxisAdaptive(),
		linechart.YLabelCellOpts(cell.FgColor(cell.ColorWhite)),
		linechart.XLabelCellOpts(cell.FgColor(cell.ColorWhite)),
	)
	if err != nil {
		panic(err)
	}

	lcBytes, err := linechart.New(
		linechart.AxesCellOpts(cell.FgColor(cell.ColorWhite)),
		linechart.YAxisAdaptive(),
		linechart.YLabelCellOpts(cell.FgColor(cell.ColorWhite)),
		linechart.XLabelCellOpts(cell.FgColor(cell.ColorWhite)),
	)
	if err != nil {
		panic(err)
	}

	legend, err := text.New()
	if err != nil {
		panic(err)
	}
	legend.Write("Legend:\n", text.WriteCellOpts(cell.FgColor(cell.ColorWhite)))
	legend.Write("██ TCP   ", text.WriteCellOpts(cell.FgColor(cell.ColorNumber(196))))
	legend.Write("██ UDP   ", text.WriteCellOpts(cell.FgColor(cell.ColorNumber(46))))
	legend.Write("██ ICMP  ", text.WriteCellOpts(cell.FgColor(cell.ColorNumber(21))))

	var mu sync.Mutex
	var rates safeStats

	ppsTCPHist := make([]float64, 0, maxPoints)
	ppsUDPHist := make([]float64, 0, maxPoints)
	ppsICMPHist := make([]float64, 0, maxPoints)

	bpsTCPHist := make([]float64, 0, maxPoints)
	bpsUDPHist := make([]float64, 0, maxPoints)
	bpsICMPHist := make([]float64, 0, maxPoints)

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current := processor.GetStats()
				now := time.Now()

				rates.mu.Lock()
				if !rates.prevTime.IsZero() {
					dt := now.Sub(rates.prevTime).Seconds()
					if dt > 0 {
						rates.ppsTCP = float64(current.TCPPackets-rates.prev.TCPPackets) / dt
						rates.ppsUDP = float64(current.UDPPackets-rates.prev.UDPPackets) / dt
						rates.ppsICMP = float64(current.ICMPPackets-rates.prev.ICMPPackets) / dt

						rates.bpsTCP = float64(current.TCPBytes-rates.prev.TCPBytes) / dt
						rates.bpsUDP = float64(current.UDPBytes-rates.prev.UDPBytes) / dt
						rates.bpsICMP = float64(current.ICMPBytes-rates.prev.ICMPBytes) / dt
					}
				}
				rates.prev = current
				rates.prevTime = now
				rates.mu.Unlock()

				mu.Lock()
				ppsTCPHist = append(ppsTCPHist, rates.ppsTCP/1000)
				ppsUDPHist = append(ppsUDPHist, rates.ppsUDP/1000)
				ppsICMPHist = append(ppsICMPHist, rates.ppsICMP/1000)

				bpsTCPHist = append(bpsTCPHist, rates.bpsTCP/1024/1024/1024)
				bpsUDPHist = append(bpsUDPHist, rates.bpsUDP/1024/1024/1024)
				bpsICMPHist = append(bpsICMPHist, rates.bpsICMP/1024/1024/1024)

				if len(ppsTCPHist) > maxPoints {
					ppsTCPHist = ppsTCPHist[len(ppsTCPHist)-maxPoints:]
					ppsUDPHist = ppsUDPHist[len(ppsUDPHist)-maxPoints:]
					ppsICMPHist = ppsICMPHist[len(ppsICMPHist)-maxPoints:]
					bpsTCPHist = bpsTCPHist[len(bpsTCPHist)-maxPoints:]
					bpsUDPHist = bpsUDPHist[len(bpsUDPHist)-maxPoints:]
					bpsICMPHist = bpsICMPHist[len(bpsICMPHist)-maxPoints:]
				}
				mu.Unlock()

				offset := 1.0

				lcPackets.Series("TCP", offsetSlice(ppsTCPHist, +offset*2), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(196))))
				lcPackets.Series("UDP", offsetSlice(ppsUDPHist, 0), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(46))))
				lcPackets.Series("ICMP", offsetSlice(ppsICMPHist, -offset*2), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(21))))

				lcBytes.Series("TCP", offsetSlice(bpsTCPHist, +offset*2), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(196))))
				lcBytes.Series("UDP", offsetSlice(bpsUDPHist, 0), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(46))))
				lcBytes.Series("ICMP", offsetSlice(bpsICMPHist, -offset*2), linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(21))))
			}
		}
	}()

	builder := grid.New()
	builder.Add(
		grid.RowHeightPerc(50,
			grid.Widget(lcPackets,
				container.Border(linestyle.Double),
				container.BorderTitle(" Packets (Kpps) "))),
		grid.RowHeightPerc(50,
			grid.Widget(lcBytes,
				container.Border(linestyle.Double),
				container.BorderTitle(" Traffic (GB/s) "))),
	)

	gridOpts, err := builder.Build()
	if err != nil {
		panic(err)
	}

	c, err := container.New(t, gridOpts...)
	if err != nil {
		panic(err)
	}

	if err := termdash.Run(ctx, t, c,
		termdash.RedrawInterval(500*time.Millisecond),
	); err != nil {
		panic(err)
	}
}

func offsetSlice(in []float64, offset float64) []float64 {
	out := make([]float64, len(in))
	for i, v := range in {
		out[i] = v + offset
	}
	return out
}
