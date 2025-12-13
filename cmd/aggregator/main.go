package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/container/grid"
	"github.com/mum4k/termdash/keyboard"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/tcell"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/mum4k/termdash/widgets/text"

	"netflow-reporter/internal"
	"netflow-reporter/pkg"
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

type viewMode int

const (
	viewCharts viewMode = iota
	viewReports
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer cancel()

	queue := internal.NewConnFlowQueue()
	go queue.Start(ctx)

	processor := internal.NewProcessor()

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

	reportText, err := text.New(text.RollContent(), text.WrapAtRunes())
	if err != nil {
		panic(err)
	}

	currentView := viewCharts

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
				bucket := queue.Dequeue()
				if bucket == nil {
					continue
				}
				if len(bucket) == 0 {
					continue
				}
				current := processor.ProcessBucket(bucket)
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

				reports := processor.GetFlowReports()
				if len(reports) == 0 {
					reportText.Reset()
					reportText.Write("No reports yet\n", text.WriteCellOpts(cell.FgColor(cell.ColorGray)))
				} else {
					reportText.Reset()
					reportText.Write("Top Flows Reports\n\n", text.WriteCellOpts(cell.FgColor(cell.ColorWhite), cell.Bold()))

					for _, r := range reports {
						reportText.Write(fmt.Sprintf("≡ %s (Top %d)\n", r.FilterName, len(r.Results)),
							text.WriteCellOpts(cell.FgColor(cell.ColorCyan), cell.Bold()))

						for i, flow := range r.Results {
							ip := net.IP(flow.IP[:])
							totalPkts := flow.TCPPacketCount + flow.UDPPacketCount + flow.ICMPPacketCount
							totalBytes := flow.TCPByteSum + flow.UDPByteSum + flow.ICMPByteSum
							direction := "incoming"
							if flow.Direction == 1 {
								direction = "outgoing"
							}
							line := fmt.Sprintf("%2d. IP: %s | Pkts: %s | Bytes: %s | ISP: %s | Country: %s | Direction: %s",
								i+1,
								ip.String(),
								formatNumber(totalPkts),
								formatBytes(totalBytes),
								pkg.GetIspName(flow.ISP),
								pkg.GetCountryName(flow.Country),
								direction)

							reportText.Write(line + "\n")
						}
						reportText.Write("\n")
					}
				}
			}
		}
	}()

	updateContainer := func(c *container.Container) error {
		builder := grid.New()
		if currentView == viewCharts {

			builder.Add(
				grid.RowHeightPerc(50,
					grid.Widget(lcPackets,
						container.Border(linestyle.Round),
						container.BorderColor(cell.ColorBlue),
						container.BorderTitle(" Packets (Kpps) "))),
				grid.RowHeightPerc(50,
					grid.Widget(lcBytes,
						container.Border(linestyle.Round),
						container.BorderColor(cell.ColorRed),
						container.BorderTitle(" Traffic (GB/s) "))),
			)
		} else {
			builder.Add(
				grid.Widget(reportText,
					container.Border(linestyle.Round),
					container.BorderColor(cell.ColorCyan),
					container.BorderTitle(" Top Flows Reports ")))
		}

		opts, err := builder.Build()
		if err != nil {
			return err
		}

		return c.Update("root", append([]container.Option{container.Clear()}, opts...)...)
	}

	c, err := container.New(t,
		container.ID("root"),
		container.Border(linestyle.Light),
		container.BorderTitle(" NetFlow Dashboard - ← → to switch views | q to quit "),
	)
	if err != nil {
		panic(err)
	}

	updateContainer(c)

	if err := termdash.Run(ctx, t, c,
		termdash.RedrawInterval(500*time.Millisecond),
		termdash.KeyboardSubscriber(func(k *terminalapi.Keyboard) {
			switch k.Key {
			case keyboard.KeyArrowLeft, keyboard.KeyArrowRight:
				if currentView == viewCharts {
					currentView = viewReports
				} else {
					currentView = viewCharts
				}
				updateContainer(c)
			case 'q', 'Q', keyboard.KeyCtrlC, keyboard.KeyCtrlQ:
				os.Exit(1)
			}
		}),
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

func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1000000000)
}

func formatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(b)/1024/1024)
	}
	return fmt.Sprintf("%.1fGB", float64(b)/1024/1024/1024)
}
