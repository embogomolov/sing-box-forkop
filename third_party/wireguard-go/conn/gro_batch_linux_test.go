//go:build linux

package conn

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// groReader answers a read with one UDP_GRO message of datagrams filled with their index.
type groReader struct {
	segments, gsoSize int
}

func (r *groReader) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	msg := &msgs[0]
	msg.N = r.segments * r.gsoSize
	for i := 0; i < msg.N; i++ {
		msg.Buffers[0][i] = byte(i / r.gsoSize)
	}
	oob := msg.OOB[:cap(msg.OOB)]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_GRO
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(r.gsoSize))
	msg.NN = unix.CmsgSpace(sizeOfGSOData)
	msg.Addr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}
	return 1, nil
}

// A batch takes whole a GRO message of the most datagrams the kernel coalesces (64): one
// that cannot hold them all fails the read and loses every one.
func TestReceiveIPTakesWholeGROMessage(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	batch := bind.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 1<<16-1)
	}
	sizes := make([]int, batch)
	eps := make([]Endpoint, batch)

	const gsoSize = 1000 // 64 segments within one 64 KB datagram
	n, err := bind.receiveIP(&groReader{segments: udpSegmentMaxDatagrams, gsoSize: gsoSize}, nil, true, bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive with a batch of %d: %v", batch, err)
	}
	if n != udpSegmentMaxDatagrams {
		t.Fatalf("got %d datagrams from a %d-segment GRO message", n, udpSegmentMaxDatagrams)
	}
	for i := 0; i < n; i++ {
		if sizes[i] != gsoSize || bufs[i][0] != byte(i) || bufs[i][gsoSize-1] != byte(i) {
			t.Fatalf("datagram %d: size %d, first byte %d, last byte %d", i, sizes[i], bufs[i][0], bufs[i][gsoSize-1])
		}
		if eps[i] == nil {
			t.Fatalf("datagram %d has no endpoint", i)
		}
	}
}
