package xhttp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func settingsFrame(flags byte, settings ...uint32) []byte {
	payload := make([]byte, 0, len(settings)*3)
	for i := 0; i+1 < len(settings); i += 2 {
		payload = binary.BigEndian.AppendUint16(payload, uint16(settings[i]))
		payload = binary.BigEndian.AppendUint32(payload, settings[i+1])
	}
	frame := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), 0x4, flags, 0, 0, 0, 0}
	return append(frame, payload...)
}

// oneByteConn delivers what it holds a byte per read.
type oneByteConn struct {
	net.Conn
	data *bytes.Reader
}

func (c *oneByteConn) Read(b []byte) (int, error) {
	return c.data.Read(b[:min(len(b), 1)])
}

func TestFrameSizeCap(t *testing.T) {
	const initialWindow, maxFrameSize = 0x4, 0x5
	data := []byte("after the frame")
	cases := map[string]struct {
		input, expected []byte
	}{
		"lowered": {
			append(settingsFrame(0, initialWindow, 1<<20, maxFrameSize, 1<<20), data...),
			append(settingsFrame(0, initialWindow, 1<<20, maxFrameSize, 16384), data...),
		},
		"already small": {
			append(settingsFrame(0, maxFrameSize, 16384), data...),
			append(settingsFrame(0, maxFrameSize, 16384), data...),
		},
		"not settings": {
			append([]byte{0, 0, 2, 0x1, 0x4, 0, 0, 0, 1, 1, 2}, settingsFrame(0, maxFrameSize, 1<<20)...),
			append([]byte{0, 0, 2, 0x1, 0x4, 0, 0, 0, 1, 1, 2}, settingsFrame(0, maxFrameSize, 1<<20)...),
		},
		"acknowledgement": {
			settingsFrame(0x1), settingsFrame(0x1),
		},
	}
	for name, c := range cases {
		for _, split := range []bool{false, true} {
			var conn net.Conn = &oneByteConn{data: bytes.NewReader(c.input)}
			if !split {
				reader := bytes.NewReader(c.input)
				conn = &readerConn{reader}
			}
			output, err := io.ReadAll(&frameSizeCapConn{Conn: conn})
			require.NoError(t, err, name)
			require.Equal(t, c.expected, output, name)
		}
	}
}

type readerConn struct {
	*bytes.Reader
}

func (c *readerConn) Close() error                     { return nil }
func (c *readerConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *readerConn) LocalAddr() net.Addr              { return nil }
func (c *readerConn) RemoteAddr() net.Addr             { return nil }
func (c *readerConn) SetDeadline(time.Time) error      { return nil }
func (c *readerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readerConn) SetWriteDeadline(time.Time) error { return nil }
