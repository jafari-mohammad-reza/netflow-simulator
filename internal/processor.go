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
	"time"
)

type Processor struct {
	mu            sync.RWMutex
	sequence      atomic.Int32
	flowTrie      *FlowTrie
	flowHistory   *FlowTrie // get merge with flow. history each 240 sequence
	Reports       []Report
	ruleEvaluator *RuleEvaluator
}

func NewProcessor() *Processor {
	ruleEvaluator, err := NewRuleEvaluator()
	if err != nil {
		panic(fmt.Errorf("failed to create rule evaluator: %s", err.Error()))
	}
	return &Processor{
		flowTrie:      NewFlowTrie(),
		flowHistory:   NewFlowTrie(),
		mu:            sync.RWMutex{},
		sequence:      atomic.Int32{},
		Reports:       make([]Report, 1),
		ruleEvaluator: ruleEvaluator,
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
	start := time.Now()
	mu := sync.Mutex{}
	fmt.Println("processing bucket of size:", len(bucket))
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
	ipMap = nil
	localMaps = nil
	runtime.GC()
	p.mu.Unlock()
	p.sequence.Add(1)
	if p.sequence.Load()%240 == 0 {
		fmt.Println("merging flow history tree")
		start := time.Now()
		p.mu.Lock()
		p.flowHistory.MergeTree(p.flowTrie)
		p.flowTrie = NewFlowTrie()
		p.sequence.Swap(0)
		p.mu.Unlock()
		go p.ReportHistoryStats()
		fmt.Println("merged flow history tree in:", time.Since(start))
	}
	fmt.Println("processed bucket in:", time.Since(start))
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
	filters := make([]Filter, 0)

	reports := make([]Report, 0)

	history := p.flowHistory.WalkValues()
	sampleFlow := history[0]
	t := reflect.TypeOf(sampleFlow)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		filters = append(filters, NewFilter(field.Name, 10))
	}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	for _, filter := range filters {
		val := reflect.ValueOf(sampleFlow).Elem().FieldByName(filter.Field)
		if !val.IsValid() {
			continue
		}
		wg.Go(func() {
			historyCp := make([]*AggregatedFlow, len(history))
			copy(historyCp, history)
			switch val.Kind() {
			case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				sort.Slice(historyCp, func(i, j int) bool {
					vi := reflect.ValueOf(historyCp[i]).Elem().FieldByName(filter.Field)
					vj := reflect.ValueOf(historyCp[j]).Elem().FieldByName(filter.Field)
					return vi.Uint() > vj.Uint()
				})
			case reflect.Float64:
				sort.Slice(historyCp, func(i, j int) bool {
					vi := reflect.ValueOf(historyCp[i]).Elem().FieldByName(filter.Field)
					vj := reflect.ValueOf(historyCp[j]).Elem().FieldByName(filter.Field)
					return vi.Float() > vj.Float()
				})
			case reflect.Int8, reflect.Array:
				sort.Slice(historyCp, func(i, j int) bool {

					viTcp := reflect.ValueOf(historyCp[i]).Elem().FieldByName("TCPPacketCount")
					viUdp := reflect.ValueOf(historyCp[i]).Elem().FieldByName("UDPPacketCount")
					viIcmp := reflect.ValueOf(historyCp[i]).Elem().FieldByName("ICMPPacketCount")
					vi := viTcp.Uint() + viUdp.Uint() + viIcmp.Uint()

					vjTcp := reflect.ValueOf(historyCp[j]).Elem().FieldByName("TCPPacketCount")
					vjUdp := reflect.ValueOf(historyCp[j]).Elem().FieldByName("UDPPacketCount")
					vjIcmp := reflect.ValueOf(historyCp[j]).Elem().FieldByName("ICMPPacketCount")
					vj := vjTcp.Uint() + vjUdp.Uint() + vjIcmp.Uint()

					return vi > vj
				})
			}
			mu.Lock()
			count := min(filter.Count, len(historyCp))
			top := historyCp[:count]
			reports = append(reports, Report{
				FilterName: filter.Field,
				Results:    top,
			})
			mu.Unlock()
		})
	}
	wg.Wait()
	p.mu.RLock()
	p.Reports = reports
	p.mu.RUnlock()
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
