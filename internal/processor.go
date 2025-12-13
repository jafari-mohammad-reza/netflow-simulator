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

func (p *Processor) ProcessBucket(bucket []pkg.NetflowPacket) error {
	mu := sync.Mutex{}

	threads := runtime.GOMAXPROCS(0)
	n := len(bucket)
	chunkSize := (n + threads - 1) / threads
	chunks := make([][]pkg.NetflowPacket, 0, threads)

	for i := 0; i < n; i += chunkSize {
		j := min(i+chunkSize, n)
		chunks = append(chunks, bucket[i:j])
	} // balanced junk sizes
	ipMap := make(map[[16]byte]AggregatedFlow, len(bucket))
	localMaps := make([]map[[16]byte]AggregatedFlow, 0, len(chunks))
	wg := sync.WaitGroup{}
	for _, chunk := range chunks {
		// agg chunk in local thread ip map and then merge ipMaps of each thread
		wg.Go(func() {
			localMap := make(map[[16]byte]AggregatedFlow, len(chunk)/2) // rough estimate
			for _, item := range chunk {
				ip, err := ParseIp(item.IP)
				if err != nil {
					continue
				}
				existing, ok := localMap[ip]

				ispIndex := pkg.GetIspIndex(item.ISP)
				if ispIndex == -1 {
					ispIndex = pkg.AddIsp(item.ISP)
				}
				countryIndex := pkg.GetCountryIndex(item.Country)
				if countryIndex == -1 {
					countryIndex = pkg.AddCountry(item.Country)
				}
				direction := int(0)
				if item.Direction == "OUT" {
					direction = 1
				}
				entry := AggregatedFlow{
					IP:        ip, // make the string ip a 16 byte array
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
				if !ok {
					localMap[ip] = entry
				} else {
					existing.TCPPacketCount += entry.TCPPacketCount
					existing.TCPByteSum += entry.TCPByteSum
					existing.UDPPacketCount += entry.UDPPacketCount
					existing.UDPByteSum += entry.UDPByteSum
					existing.ICMPPacketCount += entry.ICMPPacketCount
					existing.ICMPByteSum += entry.ICMPByteSum
					localMap[ip] = existing
				}
			}
			mu.Lock()
			localMaps = append(localMaps, localMap)
			mu.Unlock()
		})
	}
	wg.Wait()
	// merge localMaps into global ipMap

	for _, localMap := range localMaps {
		for ip, flows := range localMap {
			existing, ok := ipMap[ip]
			if !ok {
				ipMap[ip] = flows
			} else {
				existing.TCPPacketCount += flows.TCPPacketCount
				existing.TCPByteSum += flows.TCPByteSum
				existing.UDPPacketCount += flows.UDPPacketCount
				existing.UDPByteSum += flows.UDPByteSum
				existing.ICMPPacketCount += flows.ICMPPacketCount
				existing.ICMPByteSum += flows.ICMPByteSum
				ipMap[ip] = existing
			}
		}
	}

	// lock the heap buckets, merge with local aggregated flows and increase the sequence
	p.mu.Lock()
	for _, flow := range ipMap {
		f := flow
		p.flowTrie.InsertMerge(&f, false)
	}
	go p.ReportFlowStats()
	ipMap = nil
	localMaps = nil
	runtime.GC()
	p.mu.Unlock()
	p.sequence.Add(1)
	if p.sequence.Load()%240 == 0 {
		p.mu.Lock()
		p.flowHistory.MergeTree(p.flowTrie)
		p.flowTrie = NewFlowTrie()
		p.sequence.Swap(0)
		p.mu.Unlock()
		go p.ReportHistoryStats()
	}

	return nil
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
	TCPPackets  uint64
	UDPPackets  uint64
	ICMPPackets uint64
	TCPBytes    uint64
	UDPBytes    uint64
	ICMPBytes   uint64
}

func (p *Processor) GetStats() FlowStats {
	flows := p.flowTrie.WalkValues()
	TCPPackets := uint64(0)
	UDPPackets := uint64(0)
	ICMPPackets := uint64(0)
	TCPBytes := uint64(0)
	UDPBytes := uint64(0)
	ICMPBytes := uint64(0)
	for _, flow := range flows {
		TCPPackets += flow.TCPPacketCount
		UDPPackets += flow.UDPPacketCount
		ICMPPackets += flow.ICMPPacketCount
		TCPBytes += flow.TCPByteSum
		UDPBytes += flow.UDPByteSum
		ICMPBytes += flow.ICMPByteSum
	}
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
