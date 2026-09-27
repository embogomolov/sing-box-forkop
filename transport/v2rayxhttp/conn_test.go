package xhttp

import (
	"errors"
	"testing"

	"golang.org/x/net/http2"
)

var streamReset = http2.StreamError{StreamID: 21, Code: http2.ErrCodeInternal, Cause: errors.New("received from peer")}

type resetBody struct{}

func (resetBody) Read([]byte) (int, error) { return 0, streamReset }

func (resetBody) Close() error { return nil }

// An HTTP/2 client reading this conn through crypto/tls - DoH or a download
// with a detour - keeps a non-net.Error read error and gets it back on every
// read, and x/net's read loop continues on an http2.StreamError forever.
func TestSplitConnHidesStreamError(t *testing.T) {
	conn := &splitConn{reader: resetBody{}}
	_, err := conn.Read(make([]byte, 16))
	var streamError http2.StreamError
	if err == nil || errors.As(err, &streamError) {
		t.Fatalf("stream reset reached the reader as %T: %v", err, err)
	}
	if err.Error() != streamReset.Error() {
		t.Fatalf("stream reset reads %q", err)
	}
}
