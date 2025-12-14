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
			return uint16(byteIdx<<3) + uint16(clz8(x)), false
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

			if isMerge {
				TCPPacketCountUniformed := float64(merged.TCPPacketCount) / 240 / 15
				TCPByteSumUniformed := float64(merged.TCPByteSum) / 240 / 15
				UDPPacketCountUniformed := float64(merged.UDPPacketCount) / 240 / 15
				UDPByteSumUniformed := float64(merged.UDPByteSum) / 240 / 15
				ICMPPacketCountUniformed := float64(merged.ICMPPacketCount) / 240 / 15
				ICMPByteSumUniformed := float64(merged.ICMPByteSum) / 240 / 15

				if merged.Sequence > 1 {
					merged.TCPPacketCountUniformed = ((TCPPacketCountUniformed * 2) + merged.TCPPacketCountUniformed) / 3
					merged.TCPByteSumUniformed = ((TCPByteSumUniformed * 2) + merged.TCPByteSumUniformed) / 3
					merged.UDPPacketCountUniformed = ((UDPPacketCountUniformed * 2) + merged.UDPPacketCountUniformed) / 3
					merged.UDPByteSumUniformed = ((UDPByteSumUniformed * 2) + merged.UDPByteSumUniformed) / 3
					merged.ICMPPacketCountUniformed = ((ICMPPacketCountUniformed * 2) + merged.ICMPPacketCountUniformed) / 3
					merged.ICMPByteSumUniformed = ((ICMPByteSumUniformed * 2) + merged.ICMPByteSumUniformed) / 3
				} else {
					merged.TCPPacketCountUniformed = TCPPacketCountUniformed
					merged.TCPByteSumUniformed = TCPByteSumUniformed
					merged.UDPPacketCountUniformed = UDPPacketCountUniformed
					merged.UDPByteSumUniformed = UDPByteSumUniformed
					merged.ICMPPacketCountUniformed = ICMPPacketCountUniformed
					merged.ICMPByteSumUniformed = ICMPByteSumUniformed
				}

				merged.TCPPacketCount = 0
				merged.TCPByteSum = 0
				merged.UDPPacketCount = 0
				merged.UDPByteSum = 0
				merged.ICMPPacketCount = 0
				merged.ICMPByteSum = 0
				merged.Sequence += 1
			}

			newLeafNode := (*anyNode)(unsafe.Pointer(newLeaf(merged)))

			if parent == nil {
				if t.root.CompareAndSwap(cur, newLeafNode) {
					return
				}
				continue
			}

			if dirLeft {
				if parent.left.CompareAndSwap(cur, newLeafNode) {
					return
				}
			} else {
				if parent.right.CompareAndSwap(cur, newLeafNode) {
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
func (t *FlowTrie) MergeTree(other *FlowTrie, seqMerge bool) error {
	root := other.root.Load()
	if root == nil {
		return nil
	}

	var mergeNode func(n *anyNode) error
	mergeNode = func(n *anyNode) error {
		if n == nil {
			return nil
		}
		hdr := (*nodeHeader)(unsafe.Pointer(n))
		if hdr.typ == nodeLeaf {
			leaf := asLeaf(n)
			if leaf.data != nil {
				copied := flowCopy(leaf.data)
				t.InsertMerge(copied, seqMerge)
			}
			return nil
		}
		in := asInternal(n)
		left := in.left.Load()
		right := in.right.Load()

		if left != nil {
			if err := mergeNode(left); err != nil {
				return err
			}
		}
		if right != nil {
			if err := mergeNode(right); err != nil {
				return err
			}
		}
		return nil
	}

	return mergeNode(root)
}
func (t *FlowTrie) WalkValues() []*AggregatedFlow {
	var out []*AggregatedFlow
	root := t.root.Load()
	if root == nil {
		return out
	}

	var walk func(n *anyNode)
	walk = func(n *anyNode) {
		if n == nil {
			return
		}
		hdr := (*nodeHeader)(unsafe.Pointer(n))
		if hdr.typ == nodeLeaf {
			leaf := asLeaf(n)
			if leaf.data != nil {
				out = append(out, leaf.data)
			}
			return
		}
		in := asInternal(n)
		walk(in.left.Load())
		walk(in.right.Load())
	}

	walk(root)
	return out
}

func (t *FlowTrie) Filter(predicate func(*AggregatedFlow) bool) []*AggregatedFlow {
	var out []*AggregatedFlow
	for _, v := range t.WalkValues() {
		if predicate(v) {
			out = append(out, v)
		}
	}
	return out
}

func flowCopy(src *AggregatedFlow) *AggregatedFlow {
	dst := new(AggregatedFlow)
	*dst = *src
	return dst
}
