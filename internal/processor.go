package internal

import (
	"fmt"
	"net"
	"netflow-reporter/pkg"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type Processor struct {
	mu          sync.RWMutex
	sequence    atomic.Int32
	flowTrie    *FlowTrie
	flowHistory *FlowTrie // get merge with flow. history each 240 sequence
}

func NewProcessor() *Processor {
	return &Processor{
		flowTrie:    NewFlowTrie(),
		flowHistory: NewFlowTrie(),
		mu:          sync.RWMutex{},
		sequence:    atomic.Int32{},
	}
}

type AggregatedFlow struct {
	IP              [16]byte
	ISP             uint8
	Country         uint8
	Direction       uint8
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

	Sequence atomic.Int32
}

func (p *Processor) ProcessBucket(bucket []pkg.NetflowPacket) error {
	start := time.Now()
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
				direction := uint8(0)
				if item.Direction == "OUT" {
					direction = 1
				}
				entry := AggregatedFlow{
					IP:        ip, // make the string ip a 16 byte array
					ISP:       uint8(ispIndex),
					Country:   uint8(countryIndex),
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
			localMaps = append(localMaps, localMap)
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
				existing.Sequence.Store(p.sequence.Load() + 1)

				ipMap[ip] = existing
			}
		}
	}

	// lock the heap buckets, merge with local aggregated flows and increase the sequence
	p.mu.Lock()
	for _, flow := range ipMap {
		p.flowTrie.InsertMerge(&flow, false)
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
		fmt.Println("merged flow history tree in:", time.Since(start))
	}
	fmt.Println("processed bucket in:", time.Since(start))
	return nil
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
