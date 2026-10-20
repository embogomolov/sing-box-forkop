//go:build !with_quic

package force_close

import "net/http"

func resetHTTP3Transport(rawTransport http.RoundTripper) (http.RoundTripper, bool) {
	return nil, false
}
