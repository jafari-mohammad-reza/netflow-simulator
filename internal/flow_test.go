package internal

import (
	"context"
	"net"
	"netflow-reporter/pkg"
	"testing"
	"time"
)

func TestProcessorProcessBucket(t *testing.T) {
	p := NewProcessor()
	bucket := make([]pkg.NetflowPacket, 0, 1000)
	for range 1000 {
		bucket = append(bucket, pkg.NetflowPacket{
			IP:        pkg.GetRandIP(),
			Protocol:  pkg.GetRandProtocol(),
			ISP:       pkg.GetRandISP(),
			Country:   pkg.GetRandCountry(),
			Direction: pkg.GetRandDirection(),
			ByteSum:   time.Now().UnixNano() % 1_000_000,
		})
	}
	if err := p.ProcessBucket(bucket); err != nil {
		t.Fatalf("failed to process bucket: %s\n", err.Error())
	}
	if p.flowTrie.root.Load() == nil {
		t.Fatalf("flow trie is empty\n")
	}
	for i, item := range bucket {
		ipByte, err := ParseIp(item.IP)
		if err != nil {
			t.Fatalf("invalid ip of %s in tree: %s", item.IP, err.Error())
		}
		flow := p.flowTrie.Lookup(ipByte)
		if flow == nil {
			t.Fatalf("%s does not exist in tree, indx: %d", item.IP, i)
		}
		ipItems := make([]pkg.NetflowPacket, 0)
		for _, bi := range bucket {
			if bi.IP == item.IP {
				ipItems = append(ipItems, bi)
			}
		}
		tcpSum := 0
		udpSum := 0
		icmpSum := 0
		for _, i := range ipItems {
			if i.Protocol == pkg.ProtocolTCP {
				tcpSum += int(i.ByteSum)
			}
			if i.Protocol == pkg.ProtocolUDP {
				udpSum += int(i.ByteSum)
			}
			if i.Protocol == pkg.ProtocolICMP {
				icmpSum += int(i.ByteSum)
			}
		}
		switch item.Protocol {
		case pkg.ProtocolTCP:

			if tcpSum != int(flow.TCPByteSum) {
				t.Fatalf("%s flow tcp byte sum is %d but the bucket item was %d", item.IP, flow.TCPByteSum, tcpSum)
			}
		case pkg.ProtocolUDP:
			if udpSum != int(flow.UDPByteSum) {
				t.Fatalf("%s flow udp byte sum is %d but the bucket item was %d", item.IP, flow.UDPByteSum, udpSum)
			}
		case pkg.ProtocolICMP:
			if icmpSum != int(flow.ICMPByteSum) {
				t.Fatalf("%s flow icmp byte sum is %d but the bucket item was %d", item.IP, flow.ICMPByteSum, icmpSum)
			}
		}
	}
}

func BenchmarkProcessorProcessBucket(b *testing.B) {
	b.ReportAllocs()

	p := NewProcessor()

	bucket := make([]pkg.NetflowPacket, 0, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		bucket = append(bucket, pkg.NetflowPacket{
			IP:        pkg.GetRandIP(),
			Protocol:  pkg.GetRandProtocol(),
			ISP:       pkg.GetRandISP(),
			Country:   pkg.GetRandCountry(),
			Direction: pkg.GetRandDirection(),
			ByteSum:   time.Now().UnixNano() % 1_000_000,
		})
	}

	for b.Loop() {
		if err := p.ProcessBucket(bucket); err != nil {
			b.Fatalf("failed: %v", err)
		}
	}
}

func TestFlowTrie(t *testing.T) {
	trie := NewFlowTrie()

	ip1 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1}
	ip2 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 2}
	ip3 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 3}

	f1 := &AggregatedFlow{
		IP:             ip1,
		ISP:            1,
		Country:        1,
		Direction:      1,
		TCPPacketCount: 10,
		TCPByteSum:     100,
	}
	f2 := &AggregatedFlow{
		IP:             ip2,
		ISP:            2,
		Country:        2,
		Direction:      1,
		UDPPacketCount: 5,
		UDPByteSum:     50,
	}
	f3 := &AggregatedFlow{
		IP:              ip1,
		TCPPacketCount:  3,
		TCPByteSum:      30,
		ICMPPacketCount: 1,
		ICMPByteSum:     7,
	}
	f4 := &AggregatedFlow{
		IP:             ip3,
		ISP:            3,
		Country:        3,
		Direction:      1,
		TCPPacketCount: 1,
		TCPByteSum:     10,
	}

	trie.InsertMerge(f1, false)
	if trie.Lookup(ip1) == nil {
		t.Fatal("missing ip1")
	}

	trie.InsertMerge(f2, false)
	if trie.Lookup(ip2) == nil {
		t.Fatal("missing ip2")
	}

	trie.InsertMerge(f3, false)
	r := trie.Lookup(ip1)
	if r == nil || r.TCPPacketCount != 13 || r.TCPByteSum != 130 || r.ICMPPacketCount != 1 {
		t.Fatal("merge failed")
	}

	other := NewFlowTrie()
	f4.Sequence = 1
	other.InsertMerge(f4, false)
	if other.Lookup(ip3) == nil {
		t.Fatal("missing ip3 in other")
	}

	err := trie.MergeTree(other)
	if err != nil {
		t.Fatal(err)
	}

	r3 := trie.Lookup(ip3)
	if r3 == nil {
		t.Fatal("merge tree failed")
	}

	if r3.TCPPacketCount != 0 || r3.TCPPacketCountUniformed == 0 {
		t.Fatal("uniform merge failed")
	}

	if trie.Lookup([16]byte{}) != nil {
		t.Fatal("unexpected lookup hit")
	}

	empty := NewFlowTrie()
	if empty.Lookup(ip1) != nil {
		t.Fatal("empty trie lookup failed")
	}

	f5 := &AggregatedFlow{
		IP:             ip3,
		TCPPacketCount: 240,
		TCPByteSum:     2400,
		Sequence:       2,
	}
	trie.InsertMerge(f5, true)
	r5 := trie.Lookup(ip3)
	if r5 == nil || r5.TCPPacketCount != 0 || r5.TCPPacketCountUniformed == 0 {
		t.Fatal("second uniform merge failed")
	}
}

func TestConnFlowQueue(t *testing.T) {
	q := NewConnFlowQueue()

	p1 := pkg.NetflowPacket{IP: "10.0.0.1"}
	p2 := pkg.NetflowPacket{IP: "10.0.0.2"}

	q.Enqueue([]pkg.NetflowPacket{p1})
	if len(q.active.Flow) != 1 {
		t.Fatal("enqueue failed")
	}

	q.active.StartedAt = time.Now().Unix() - 20
	q.Enqueue([]pkg.NetflowPacket{p2})

	if len(q.queue) != 1 {
		t.Fatal("bucket rotation failed")
	}

	if len(q.active.Flow) != 1 {
		t.Fatal("active bucket reset failed")
	}

	out := q.Dequeue()
	if len(out) != 1 || out[0].IP != "10.0.0.1" {
		t.Fatal("dequeue failed")
	}

	if q.Dequeue() != nil {
		t.Fatal("unexpected dequeue")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := q.Start(ctx)
	if err == nil {
		t.Fatal("expected context cancel")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:6071")
	if err == nil {
		ln.Close()
	}
}
