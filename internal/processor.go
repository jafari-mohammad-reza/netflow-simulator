package internal

import (
	"fmt"
	"net"
	"netflow-reporter/pkg"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

type Processor struct {
	mu             sync.RWMutex
	sequence       atomic.Int32
	flowTrie       *FlowTrie
	flowHistory    *FlowTrie // get merge with flow. history each 240 sequence
	HistoryReports []Report
	FlowReports    []Report
	ruleEvaluator  *RuleEvaluator
}

func NewProcessor() *Processor {
	ruleEvaluator, err := NewRuleEvaluator()
	if err != nil {
		panic(fmt.Errorf("failed to create rule evaluator: %s", err.Error()))
	}
	return &Processor{
		flowTrie:       NewFlowTrie(),
		flowHistory:    NewFlowTrie(),
		mu:             sync.RWMutex{},
		sequence:       atomic.Int32{},
		HistoryReports: make([]Report, 1),
		FlowReports:    make([]Report, 1),
		ruleEvaluator:  ruleEvaluator,
	}
}

type AggregatedFlow struct {
	IP              [16]byte
	ISP             int
	Country         int
	Direction       int
	TCPPacketCount  uint64
	TCPByteSum      uint64
	UDPPacketCount  uint64
	UDPByteSum      uint64
	ICMPPacketCount uint64
	ICMPByteSum     uint64

	TCPPacketCountUniformed  float64
	TCPByteSumUniformed      float64
	UDPPacketCountUniformed  float64
	UDPByteSumUniformed      float64
	ICMPPacketCountUniformed float64
	ICMPByteSumUniformed     float64

	Sequence int
}

func (p *Processor) ProcessBucket(bucket []pkg.NetflowPacket) FlowStats {
	threads := runtime.GOMAXPROCS(0)
	n := len(bucket)
	if n == 0 {
		return FlowStats{}
	}
	chunkSize := (n + threads - 1) / threads
	chunks := make([][]pkg.NetflowPacket, 0, threads)
	for i := 0; i < n; i += chunkSize {
		j := min(i+chunkSize, n)
		chunks = append(chunks, bucket[i:j])
	}

	localMaps := make([]*FlowTrie, len(chunks))
	var wg sync.WaitGroup
	wg.Add(len(chunks))

	for idx, chunk := range chunks {
		go func(idx int, chunk []pkg.NetflowPacket) {
			defer wg.Done()
			local := NewFlowTrie()
			for _, item := range chunk {
				ip, err := ParseIp(item.IP)
				if err != nil {
					continue
				}
				existing := local.Lookup(ip)
				ispIndex := pkg.GetIspIndex(item.ISP)
				if ispIndex == -1 {
					ispIndex = pkg.AddIsp(item.ISP)
				}
				countryIndex := pkg.GetCountryIndex(item.Country)
				if countryIndex == -1 {
					countryIndex = pkg.AddCountry(item.Country)
				}
				direction := 0
				if item.Direction == "OUT" {
					direction = 1
				}
				entry := AggregatedFlow{
					IP:        ip,
					ISP:       ispIndex,
					Country:   countryIndex,
					Direction: direction,
				}
				switch item.Protocol {
				case "TCP":
					entry.TCPPacketCount = 1
					entry.TCPByteSum = uint64(item.ByteSum)
				case "UDP":
					entry.UDPPacketCount = 1
					entry.UDPByteSum = uint64(item.ByteSum)
				case "ICMP":
					entry.ICMPPacketCount = 1
					entry.ICMPByteSum = uint64(item.ByteSum)
				}
				if existing == nil {
					local.InsertMerge(&entry, false)
				} else {
					existing.TCPPacketCount += entry.TCPPacketCount
					existing.TCPByteSum += entry.TCPByteSum
					existing.UDPPacketCount += entry.UDPPacketCount
					existing.UDPByteSum += entry.UDPByteSum
					existing.ICMPPacketCount += entry.ICMPPacketCount
					existing.ICMPByteSum += entry.ICMPByteSum
				}
			}
			localMaps[idx] = local
		}(idx, chunk)
	}
	wg.Wait()

	ipMap := NewFlowTrie()
	for _, local := range localMaps {
		ipMap.MergeTree(local, false)
	}

	p.mu.Lock()
	flows := ipMap.WalkValues()
	TCPPackets, UDPPackets, ICMPPackets, TCPBytes, UDPBytes, ICMPBytes := sumAggregatedFlows(flows)
	stats := FlowStats{
		TCPPackets,
		UDPPackets,
		ICMPPackets,
		TCPBytes,
		UDPBytes,
		ICMPBytes,
	}
	p.flowTrie.MergeTree(ipMap, false)
	go p.ReportFlowStats()
	p.mu.Unlock()

	p.sequence.Add(1)
	if p.sequence.Load()%240 == 0 {
		p.mu.Lock()
		p.flowHistory.MergeTree(p.flowTrie, true)
		p.flowTrie = NewFlowTrie()
		p.sequence.Swap(0)
		p.mu.Unlock()
		go p.ReportHistoryStats()
	}

	return stats
}

func sumAggregatedFlows(flows []*AggregatedFlow) (tcpPkt, udpPkt, icmpPkt, tcpBytes, udpBytes, icmpBytes uint64) {
	if len(flows) == 0 {
		return
	}

	numCPU := runtime.NumCPU()
	chunkSize := (len(flows) + numCPU - 1) / numCPU

	type partial struct {
		tcpPkt, udpPkt, icmpPkt uint64
		tcpB, udpB, icmpB       uint64
	}

	partials := make([]partial, numCPU)

	var wg sync.WaitGroup
	wg.Add(numCPU)

	for i := range numCPU {
		start := i * chunkSize
		end := min(start+chunkSize, len(flows))
		if start >= end {
			wg.Done()
			continue
		}

		go func(idx int, flows []*AggregatedFlow) {
			defer wg.Done()
			var p partial
			f := flows

			for j := 0; j < len(f); j += 4 {
				if j+3 < len(f) {
					f0 := f[j+0]
					f1 := f[j+1]
					f2 := f[j+2]
					f3 := f[j+3]

					p.tcpPkt += f0.TCPPacketCount + f1.TCPPacketCount + f2.TCPPacketCount + f3.TCPPacketCount
					p.udpPkt += f0.UDPPacketCount + f1.UDPPacketCount + f2.UDPPacketCount + f3.UDPPacketCount
					p.icmpPkt += f0.ICMPPacketCount + f1.ICMPPacketCount + f2.ICMPPacketCount + f3.ICMPPacketCount

					p.tcpB += f0.TCPByteSum + f1.TCPByteSum + f2.TCPByteSum + f3.TCPByteSum
					p.udpB += f0.UDPByteSum + f1.UDPByteSum + f2.UDPByteSum + f3.UDPByteSum
					p.icmpB += f0.ICMPByteSum + f1.ICMPByteSum + f2.ICMPByteSum + f3.ICMPByteSum
				} else {

					for ; j < len(f); j++ {
						flow := f[j]
						p.tcpPkt += flow.TCPPacketCount
						p.udpPkt += flow.UDPPacketCount
						p.icmpPkt += flow.ICMPPacketCount
						p.tcpB += flow.TCPByteSum
						p.udpB += flow.UDPByteSum
						p.icmpB += flow.ICMPByteSum
					}
				}
			}

			partials[idx] = p
		}(i, flows[start:end])
	}

	wg.Wait()

	for _, part := range partials {
		tcpPkt += part.tcpPkt
		udpPkt += part.udpPkt
		icmpPkt += part.icmpPkt
		tcpBytes += part.tcpB
		udpBytes += part.udpB
		icmpBytes += part.icmpB
	}

	return
}

type Filter struct {
	Field string
	Count int // default is 10
}

func NewFilter(field string, count int) Filter {
	c := count
	if c == 0 {
		c = 10
	}
	return Filter{
		Field: field,
		Count: c,
	}
}

type Report struct {
	FilterName string
	Results    []*AggregatedFlow
}

func (p *Processor) ReportHistoryStats() {
	history := p.flowHistory.WalkValues()
	if len(history) == 0 {
		p.mu.Lock()
		p.HistoryReports = nil
		p.mu.Unlock()
		return
	}

	reports := make([]Report, 0, 17)

	fields := []struct {
		name string
		kind reflect.Kind
	}{
		{"IP", reflect.Array},
		{"ISP", reflect.Int},
		{"Country", reflect.Int},
		{"Direction", reflect.Int},
		{"TCPPacketCount", reflect.Uint64},
		{"TCPByteSum", reflect.Uint64},
		{"UDPPacketCount", reflect.Uint64},
		{"UDPByteSum", reflect.Uint64},
		{"ICMPPacketCount", reflect.Uint64},
		{"ICMPByteSum", reflect.Uint64},
		{"TCPPacketCountUniformed", reflect.Float64},
		{"TCPByteSumUniformed", reflect.Float64},
		{"UDPPacketCountUniformed", reflect.Float64},
		{"UDPByteSumUniformed", reflect.Float64},
		{"ICMPPacketCountUniformed", reflect.Float64},
		{"ICMPByteSumUniformed", reflect.Float64},
		{"Sequence", reflect.Int},
	}

	var wg sync.WaitGroup
	wg.Add(len(fields))
	results := make(chan Report, len(fields))

	for _, f := range fields {
		go func(name string, kind reflect.Kind) {
			defer wg.Done()

			cp := make([]*AggregatedFlow, len(history))
			copy(cp, history)

			switch kind {
			case reflect.Uint64, reflect.Int:
				sort.Slice(cp, func(i, j int) bool {
					return getFieldUint(cp[i], name) > getFieldUint(cp[j], name)
				})
			case reflect.Float64:
				sort.Slice(cp, func(i, j int) bool {
					return getFieldFloat(cp[i], name) > getFieldFloat(cp[j], name)
				})
			case reflect.Array:
				sort.Slice(cp, func(i, j int) bool {
					return getTotalPackets(cp[i]) > getTotalPackets(cp[j])
				})
			}

			n := min(10, len(cp))
			results <- Report{FilterName: name, Results: cp[:n]}
		}(f.name, f.kind)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		reports = append(reports, r)
	}

	p.mu.Lock()
	p.HistoryReports = reports
	p.mu.Unlock()
}

func (p *Processor) ReportFlowStats() {
	history := p.flowTrie.WalkValues()
	if len(history) == 0 {
		p.mu.Lock()
		p.FlowReports = nil
		p.mu.Unlock()
		return
	}

	reports := make([]Report, 0, 17)

	fields := []struct {
		name string
		kind reflect.Kind
	}{
		{"IP", reflect.Array},
		{"ISP", reflect.Int},
		{"Country", reflect.Int},
		{"Direction", reflect.Int},
		{"TCPPacketCount", reflect.Uint64},
		{"TCPByteSum", reflect.Uint64},
		{"UDPPacketCount", reflect.Uint64},
		{"UDPByteSum", reflect.Uint64},
		{"ICMPPacketCount", reflect.Uint64},
		{"ICMPByteSum", reflect.Uint64},
		{"TCPPacketCountUniformed", reflect.Float64},
		{"TCPByteSumUniformed", reflect.Float64},
		{"UDPPacketCountUniformed", reflect.Float64},
		{"UDPByteSumUniformed", reflect.Float64},
		{"ICMPPacketCountUniformed", reflect.Float64},
		{"ICMPByteSumUniformed", reflect.Float64},
		{"Sequence", reflect.Int},
	}

	var wg sync.WaitGroup
	wg.Add(len(fields))
	results := make(chan Report, len(fields))

	for _, f := range fields {
		go func(name string, kind reflect.Kind) {
			defer wg.Done()

			cp := make([]*AggregatedFlow, len(history))
			copy(cp, history)

			switch kind {
			case reflect.Uint64, reflect.Int:
				sort.Slice(cp, func(i, j int) bool {
					return getFieldUint(cp[i], name) > getFieldUint(cp[j], name)
				})
			case reflect.Float64:
				sort.Slice(cp, func(i, j int) bool {
					return getFieldFloat(cp[i], name) > getFieldFloat(cp[j], name)
				})
			case reflect.Array:
				sort.Slice(cp, func(i, j int) bool {
					return getTotalPackets(cp[i]) > getTotalPackets(cp[j])
				})
			}

			n := min(10, len(cp))
			results <- Report{FilterName: name, Results: cp[:n]}
		}(f.name, f.kind)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		reports = append(reports, r)
	}

	p.mu.Lock()
	p.FlowReports = reports
	p.mu.Unlock()
}

func getFieldUint(f *AggregatedFlow, field string) uint64 {
	v := reflect.ValueOf(f).Elem().FieldByName(field)
	if v.IsValid() && v.Kind() == reflect.Uint64 {
		return v.Uint()
	}
	if v.IsValid() && (v.Kind() == reflect.Int || v.Kind() == reflect.Int32 || v.Kind() == reflect.Int64) {
		return uint64(v.Int())
	}
	return 0
}

func getFieldFloat(f *AggregatedFlow, field string) float64 {
	v := reflect.ValueOf(f).Elem().FieldByName(field)
	if v.IsValid() && v.Kind() == reflect.Float64 {
		return v.Float()
	}
	return 0
}

func getTotalPackets(f *AggregatedFlow) uint64 {
	v := reflect.ValueOf(f).Elem()
	return v.FieldByName("TCPPacketCount").Uint() +
		v.FieldByName("UDPPacketCount").Uint() +
		v.FieldByName("ICMPPacketCount").Uint()
}

func (p *Processor) ReportCandidateFlows() []CandidateFlow {
	history := p.flowHistory.WalkValues()
	candidates, err := p.ruleEvaluator.Evaluate(history)
	if err != nil {
		fmt.Printf("failed to Evaluate candidates: %s\n", err.Error())
		return nil
	}
	return candidates
}

func ParseIp(ipStr string) ([16]byte, error) {
	var out [16]byte

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return out, fmt.Errorf("invalid IP: %s", ipStr)
	}

	ip = ip.To16()
	if ip == nil {
		return out, fmt.Errorf("ip.To16 failed for: %s", ipStr)
	}

	copy(out[:], ip)
	return out, nil
}

type FlowStats struct {
	TCPPackets  uint64 `json:"TCP_Packets"`
	UDPPackets  uint64 `json:"UDP_Packets"`
	ICMPPackets uint64 `json:"ICMP_Packets"`
	TCPBytes    uint64 `json:"TCP_Bytes"`
	UDPBytes    uint64 `json:"UDP_Bytes"`
	ICMPBytes   uint64 `json:"ICMP_Bytes"`
}

func (p *Processor) GetStats() FlowStats {
	flows := p.flowTrie.WalkValues()
	TCPPackets, UDPPackets, ICMPPackets, TCPBytes, UDPBytes, ICMPBytes := sumAggregatedFlows(flows)
	return FlowStats{
		TCPPackets,
		UDPPackets,
		ICMPPackets,
		TCPBytes,
		UDPBytes,
		ICMPBytes,
	}
}
func (p *Processor) GetFlowReports() []Report {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.FlowReports
}
