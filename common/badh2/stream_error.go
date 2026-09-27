package badh2

import (
	"errors"

	"golang.org/x/net/http2"
)

type RemoteStreamError struct {
	text string
}

func (e *RemoteStreamError) Error() string {
	return e.text
}

// HideStreamError replaces an http2.StreamError, bare or wrapped, with an
// error of the same text that errors.As cannot unwrap back to it. A conn built
// on an HTTP/2 body must not pass that type on: crypto/tls keeps a read error
// that is not a net.Error and returns it on every later read, and the read
// loop of an x/net HTTP/2 client continues on a StreamError, so a client
// reading such a conn through TLS spins until the process exits.
func HideStreamError(err error) error {
	var streamError http2.StreamError
	if err != nil && errors.As(err, &streamError) {
		return &RemoteStreamError{text: err.Error()}
	}
	return err
}
