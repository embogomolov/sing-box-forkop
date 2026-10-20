package xhttp

import (
	"encoding/binary"
	"io"
	"net"
)

// maxWriteFrameSize is HTTP/2's initial frame size, what Chrome sends.
const maxWriteFrameSize = 16 * 1024

// frameSizeCapConn lowers the SETTINGS_MAX_FRAME_SIZE of the server's first SETTINGS frame to
// maxWriteFrameSize: golang.org/x/net/http2 writes a request body through a buffer of the
// server's frame size, up to 512 KiB, held until the body ends, which a streamed upload does
// with its session. A later SETTINGS frame is left alone.
type frameSizeCapConn struct {
	net.Conn
	done    bool
	pending []byte
}

// maxSettingsFrame bounds the first frame read whole; a setting is six bytes.
const maxSettingsFrame = 1024

func (c *frameSizeCapConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.done {
		return c.Conn.Read(b)
	}
	c.done = true
	frame := make([]byte, 9, 9+64)
	_, err := io.ReadFull(c.Conn, frame)
	if err != nil {
		return 0, err
	}
	length := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	const frameTypeSettings, flagAck = 0x4, 0x1
	if frame[3] == frameTypeSettings && frame[4]&flagAck == 0 && length <= maxSettingsFrame && length%6 == 0 {
		payload := make([]byte, length)
		_, err = io.ReadFull(c.Conn, payload)
		if err != nil {
			return 0, err
		}
		const settingMaxFrameSize = 0x5
		for i := 0; i+6 <= len(payload); i += 6 {
			if binary.BigEndian.Uint16(payload[i:]) == settingMaxFrameSize && binary.BigEndian.Uint32(payload[i+2:]) > maxWriteFrameSize {
				binary.BigEndian.PutUint32(payload[i+2:], maxWriteFrameSize)
			}
		}
		frame = append(frame, payload...)
	}
	n := copy(b, frame)
	c.pending = frame[n:]
	return n, nil
}

func (c *frameSizeCapConn) Upstream() any {
	return c.Conn
}
