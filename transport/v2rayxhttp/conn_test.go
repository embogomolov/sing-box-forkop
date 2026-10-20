package xhttp

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	sbufio "github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
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

// countingReader records the reads that had to wait for data: the read waiter must make
// those with its probe only, never with the copy loop's buffer.
type countingReader struct {
	reader     *io.PipeReader
	access     sync.Mutex
	waitedWith []int
}

func (r *countingReader) Read(b []byte) (int, error) {
	start := time.Now()
	n, err := r.reader.Read(b)
	if time.Since(start) > 10*time.Millisecond {
		r.access.Lock()
		r.waitedWith = append(r.waitedWith, len(b))
		r.access.Unlock()
	}
	return n, err
}

func (r *countingReader) Close() error {
	return r.reader.Close()
}

// The copy loop finds the read waiter, waits for data on the probe and gets every byte in
// order; no read that waited held more than the probe.
func TestSplitConnWaitsOnTheProbe(t *testing.T) {
	pipeReader, pipeWriter := io.Pipe()
	reader := &countingReader{reader: pipeReader}
	conn := &splitConn{reader: reader, writer: nopWriteCloser{}}
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := sbufio.Copy(&output, conn)
		done <- err
	}()
	var sent bytes.Buffer
	for i := 0; i < 5; i++ {
		chunk := bytes.Repeat([]byte{byte('a' + i)}, 300*(i+1))
		sent.Write(chunk)
		_, err := pipeWriter.Write(chunk)
		require.NoError(t, err)
		time.Sleep(30 * time.Millisecond)
	}
	pipeWriter.Close()
	require.NoError(t, <-done)
	require.Equal(t, sent.Bytes(), output.Bytes())
	reader.access.Lock()
	defer reader.access.Unlock()
	require.NotEmpty(t, reader.waitedWith)
	for _, length := range reader.waitedWith {
		require.LessOrEqual(t, length, probeSize, "a read waited for data holding the copy buffer")
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriteCloser) Close() error                { return nil }
