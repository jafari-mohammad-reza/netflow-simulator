package internal

import (
	"sync/atomic"
	"unsafe"
)

type nodeType uint8

const (
	nodeLeaf nodeType = iota
	nodeInternal
)

type nodeHeader struct {
	typ nodeType
}

type internalNode struct {
	h      nodeHeader
	bitIdx uint16
	_      uint16

	left  atomic.Pointer[anyNode]
	right atomic.Pointer[anyNode]
}

type leafNode struct {
	h    nodeHeader
	data *AggregatedFlow
}

type anyNode struct {
	_ uintptr
}

func newLeaf(v *AggregatedFlow) *leafNode {
	return &leafNode{h: nodeHeader{typ: nodeLeaf}, data: v}
}

type FlowTrie struct { // bitwise radix
	root atomic.Pointer[anyNode]
}

func NewFlowTrie() *FlowTrie {
	return &FlowTrie{}
}

func asLeaf(p *anyNode) *leafNode {
	return (*leafNode)(unsafe.Pointer(p))
}
func asInternal(p *anyNode) *internalNode {
	return (*internalNode)(unsafe.Pointer(p))
}

func getBit(ip *[16]byte, i uint16) uint8 {
	byteIdx := i >> 3
	bitInByte := 7 - (i & 7)
	return (ip[byteIdx] >> bitInByte) & 1
}

func firstDiffBit(a, b *[16]byte) (uint16, bool) {
	for byteIdx := 0; byteIdx < 16; byteIdx++ {
		av := a[byteIdx]
		bv := b[byteIdx]
		if av != bv {
			x := av ^ bv

			leading := uint16(7 - clz8(x))
			return uint16(byteIdx<<3) + leading, false
		}
	}
	return 0, true
}

func clz8(x byte) int {

	switch {
	case x&0x80 != 0:
		return 0
	case x&0x40 != 0:
		return 1
	case x&0x20 != 0:
		return 2
	case x&0x10 != 0:
		return 3
	case x&0x08 != 0:
		return 4
	case x&0x04 != 0:
		return 5
	case x&0x02 != 0:
		return 6
	case x&0x01 != 0:
		return 7
	default:
		return 8
	}
}

func (t *FlowTrie) Lookup(ip [16]byte) *AggregatedFlow {
	root := t.root.Load()
	if root == nil {
		return nil
	}
	n := root
	for {

		hdr := (*nodeHeader)(unsafe.Pointer(n))
		if hdr.typ == nodeLeaf {
			leaf := asLeaf(n)
			if leaf.data != nil && leaf.data.IP == ip {
				return leaf.data
			}
			return nil
		}
		in := asInternal(n)
		b := getBit(&ip, in.bitIdx)
		if b == 0 {
			n = in.left.Load()
		} else {
			n = in.right.Load()
		}
		if n == nil {
			return nil
		}
	}
}

func mergeInto(dst *AggregatedFlow, src *AggregatedFlow) {
	if dst.ISP == 0 {
		dst.ISP = src.ISP
	}
	if dst.Country == 0 {
		dst.Country = src.Country
	}
	if dst.Direction == 0 {
		dst.Direction = src.Direction
	}
	dst.TCPPacketCount += src.TCPPacketCount
	dst.TCPByteSum += src.TCPByteSum
	dst.UDPPacketCount += src.UDPPacketCount
	dst.UDPByteSum += src.UDPByteSum
	dst.ICMPPacketCount += src.ICMPPacketCount
	dst.ICMPByteSum += src.ICMPByteSum
}

func (t *FlowTrie) InsertMerge(flow *AggregatedFlow, isMerge bool) {
	for {
		root := t.root.Load()

		if root == nil {
			newLeaf := (*anyNode)(unsafe.Pointer(newLeaf(flowCopy(flow))))
			if t.root.CompareAndSwap(nil, newLeaf) {
				return
			}

			continue
		}

		var parent *internalNode
		var parentPtr *atomic.Pointer[anyNode]
		var dirLeft bool
		cur := root
		for {
			hdr := (*nodeHeader)(unsafe.Pointer(cur))
			if hdr.typ == nodeLeaf {
				break
			}
			in := asInternal(cur)
			parent = in
			if getBit(&flow.IP, in.bitIdx) == 0 {
				parentPtr = &in.left
				dirLeft = true
				cur = in.left.Load()
			} else {
				parentPtr = &in.right
				dirLeft = false
				cur = in.right.Load()
			}
			if isMerge {

				TCPPacketCountUniformed := float64(flow.TCPPacketCount) / 240 / 15 // an hour is 240 15-second intervals
				TCPByteSumUniformed := float64(flow.TCPByteSum) / 240 / 15
				UDPPacketCountUniformed := float64(flow.UDPPacketCount) / 240 / 15
				UDPByteSumUniformed := float64(flow.UDPByteSum) / 240 / 15
				ICMPPacketCountUniformed := float64(flow.ICMPPacketCount) / 240 / 15
				ICMPByteSumUniformed := float64(flow.ICMPByteSum) / 240 / 15

				if flow.Sequence.Load() > 1 {
					flow.TCPPacketCountUniformed = ((TCPPacketCountUniformed * 2) + flow.TCPPacketCountUniformed) / 3
					flow.TCPByteSumUniformed = ((TCPByteSumUniformed * 2) + flow.TCPByteSumUniformed) / 3
					flow.UDPPacketCountUniformed = ((UDPPacketCountUniformed * 2) + flow.UDPPacketCountUniformed) / 3
					flow.UDPByteSumUniformed = ((UDPByteSumUniformed * 2) + flow.UDPByteSumUniformed) / 3
					flow.ICMPPacketCountUniformed = ((ICMPPacketCountUniformed * 2) + flow.ICMPPacketCountUniformed) / 3
					flow.ICMPByteSumUniformed = ((ICMPByteSumUniformed * 2) + flow.ICMPByteSumUniformed) / 3
				} else {
					flow.TCPPacketCountUniformed = TCPPacketCountUniformed
					flow.TCPByteSumUniformed = TCPByteSumUniformed
					flow.UDPPacketCountUniformed = UDPPacketCountUniformed
					flow.UDPByteSumUniformed = UDPByteSumUniformed
					flow.ICMPPacketCountUniformed = ICMPPacketCountUniformed
					flow.ICMPByteSumUniformed = ICMPByteSumUniformed
				}

				flow.TCPPacketCount = 0
				flow.TCPByteSum = 0
				flow.UDPPacketCount = 0
				flow.UDPByteSum = 0
				flow.ICMPPacketCount = 0
				flow.ICMPByteSum = 0
				flow.Sequence.Add(1)
			}
			if cur == nil {

				newNode := (*anyNode)(unsafe.Pointer(newLeaf(flowCopy(flow))))
				if parentPtr.CompareAndSwap(nil, newNode) {
					return
				}

				break
			}
		}

		leaf := asLeaf(cur)
		if leaf == nil || leaf.data == nil {

			continue
		}

		if leaf.data.IP == flow.IP {

			merged := flowCopy(leaf.data)
			mergeInto(merged, flow)
			newLeaf := (*anyNode)(unsafe.Pointer(newLeaf(merged)))

			if parent == nil {

				if t.root.CompareAndSwap(cur, newLeaf) {
					return
				}

				continue
			}

			if dirLeft {
				if parent.left.CompareAndSwap(cur, newLeaf) {
					return
				}
			} else {
				if parent.right.CompareAndSwap(cur, newLeaf) {
					return
				}
			}

			continue
		}

		otherKey := &leaf.data.IP
		bit, _ := firstDiffBit(&flow.IP, otherKey)

		bFlow := getBit(&flow.IP, bit)
		var leftPtr *anyNode
		var rightPtr *anyNode
		if bFlow == 0 {
			leftPtr = (*anyNode)(unsafe.Pointer(newLeaf(flowCopy(flow))))
			rightPtr = cur
		} else {
			leftPtr = cur
			rightPtr = (*anyNode)(unsafe.Pointer(newLeaf(flowCopy(flow))))
		}

		in := &internalNode{h: nodeHeader{typ: nodeInternal}, bitIdx: bit}
		in.left.Store(leftPtr)
		in.right.Store(rightPtr)
		newInternalAny := (*anyNode)(unsafe.Pointer(in))

		if parent == nil {

			if t.root.CompareAndSwap(cur, newInternalAny) {
				return
			}

			continue
		}

		if dirLeft {
			if parent.left.CompareAndSwap(cur, newInternalAny) {
				return
			}
		} else {
			if parent.right.CompareAndSwap(cur, newInternalAny) {
				return
			}
		}

	}
}

// merge with another tree using same logic as InsertMerge but aggregate packet fields and set them to zero
func (t *FlowTrie) MergeTree(other *FlowTrie) error {
	root := other.root.Load()
	if root == nil {
		return nil
	}

	var mergeNode func(n *anyNode) error
	mergeNode = func(n *anyNode) error {
		hdr := (*nodeHeader)(unsafe.Pointer(n))
		if hdr.typ == nodeLeaf {
			leaf := asLeaf(n)
			if leaf.data != nil {
				t.InsertMerge(leaf.data, true)
			}
			return nil
		}
		in := asInternal(n)
		left := in.left.Load()
		if left != nil {
			if err := mergeNode(left); err != nil {
				return err
			}
		}
		right := in.right.Load()
		if right != nil {
			if err := mergeNode(right); err != nil {
				return err
			}
		}
		return nil
	}

	return mergeNode(root)
}

func flowCopy(src *AggregatedFlow) *AggregatedFlow {
	dst := new(AggregatedFlow)
	*dst = *src
	return dst
}
