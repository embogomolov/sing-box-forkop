//go:build !with_quic

package xhttp

import (
	"context"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// NewClient refuses HTTP/3 in a build without QUIC, so nothing reaches this.
func newHTTP3Transport(ctx context.Context, dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config, keepAlivePeriod time.Duration) http.RoundTripper {
	return nil
}
