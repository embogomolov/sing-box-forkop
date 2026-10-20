//go:build with_quic

package force_close

import (
	"net/http"

	"github.com/sagernet/quic-go/http3"
)

func resetHTTP3Transport(rawTransport http.RoundTripper) (http.RoundTripper, bool) {
	transport, ok := rawTransport.(*http3.Transport)
	if !ok {
		return nil, false
	}
	transport.Close()
	return transport, true
}
