//go:build with_gvisor && linux

package tailscale

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/tailscale/net/batching"
	wgconn "github.com/sagernet/wireguard-go/conn"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// magicsock sizes its batch by conn.IdealBatchSize and reads two UDP GRO messages of up to 64
// datagrams into its end; loopback hands a GRO socket each UDP_SEGMENT send whole.
func TestReceiveBatchTakesTwoCoalescedReads(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	conn, isBatching := batching.TryUpgradeToConn(receiver, "udp4", wgconn.IdealBatchSize, "", nil).(batching.Conn)
	if !isBatching {
		t.Skip("the kernel reads no message batches")
	}
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const datagram, datagrams = 500, 64
	segment := make([]byte, unix.CmsgSpace(2))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&segment[0]))
	header.Level, header.Type = unix.SOL_UDP, unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(segment[unix.CmsgLen(0):], datagram)
	for range 2 {
		_, _, err = sender.WriteMsgUDP(make([]byte, datagram*datagrams), segment, nil)
		if err != nil {
			t.Skip("the kernel sends no UDP segments: ", err)
		}
	}

	messages := make([]ipv6.Message, wgconn.IdealBatchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 1<<16)}
		messages[i].OOB = make([]byte, batching.MinControlMessageSize())
	}
	receiver.SetReadDeadline(time.Now().Add(5 * time.Second))
	for received := 0; received < 2*datagrams; {
		for i := range messages {
			messages[i].N, messages[i].NN = 0, 0
			messages[i].OOB = messages[i].OOB[:cap(messages[i].OOB)]
		}
		n, err := conn.ReadBatch(messages, 0)
		if err != nil {
			t.Fatalf("after %d datagrams: %v", received, err)
		}
		for _, message := range messages[:n] {
			if message.N != 0 && message.N != datagram {
				t.Fatalf("a datagram of %d bytes, want %d", message.N, datagram)
			}
			if message.N != 0 {
				received++
			}
		}
	}
}
