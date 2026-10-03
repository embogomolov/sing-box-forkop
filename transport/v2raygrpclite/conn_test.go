package v2raygrpclite

import (
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

var streamReset = http2.StreamError{StreamID: 21, Code: http2.ErrCodeInternal, Cause: errors.New("received from peer")}

type resetBody struct{}

func (resetBody) Read([]byte) (int, error) { return 0, streamReset }

// An HTTP/2 client reading this conn through crypto/tls - DoH or a download
// with a detour - keeps a non-net.Error read error and gets it back on every
// read, and x/net's read loop continues on an http2.StreamError forever.
func TestGunConnHidesStreamError(t *testing.T) {
	for name, setup := range map[string]func(*GunConn){
		"body read":  func(conn *GunConn) { conn.setup(resetBody{}, nil) },
		"late setup": func(conn *GunConn) { conn.setup(nil, streamReset) },
	} {
		t.Run(name, func(t *testing.T) {
			conn := newLateGunConn(io.Discard, func() {})
			setup(conn)
			_, err := conn.Read(make([]byte, 16))
			var streamError http2.StreamError
			if err == nil || errors.As(err, &streamError) {
				t.Fatalf("stream reset reached the reader as %T: %v", err, err)
			}
			if err.Error() != streamReset.Error() {
				t.Fatalf("stream reset reads %q", err)
			}
		})
	}
}

// When RoundTrip fails (the server cannot be dialled), the request never establishes and
// nothing reads the request-body pipe. A Write that started before the failure must not
// block for ever: the client closes the read end of the pipe with the error, so the write
// returns that error. Without the fix this test hangs and the goroutine and socket of every
// such attempt leak.
func TestLateGunConnWriteUnblocksOnSetupError(t *testing.T) {
	t.Parallel()
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()
	_, cancel := context.WithCancel(context.Background())
	conn := newLateGunConn(pipeWriter, cancel)

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("handshake"))
		writeErr <- err
	}()

	// the write is now blocked on the pipe that nobody reads
	select {
	case <-writeErr:
		t.Fatal("write returned before the request failed")
	case <-time.After(100 * time.Millisecond):
	}

	pipeReader.CloseWithError(syscall.ECONNREFUSED)
	conn.setup(nil, syscall.ECONNREFUSED)

	// the blocked write returns the dial error itself instead of hanging (the field case: the
	// server refuses or is blackholed)
	select {
	case err := <-writeErr:
		require.ErrorIs(t, err, syscall.ECONNREFUSED)
	case <-time.After(5 * time.Second):
		t.Fatal("write still blocked after setup failed: the goroutine and socket would leak")
	}

	// a write after the failure also returns at once, it does not block
	done := make(chan struct{})
	go func() {
		conn.Write([]byte("after"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a write after the failure blocked")
	}
}
