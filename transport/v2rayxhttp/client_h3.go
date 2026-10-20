//go:build with_quic

package xhttp

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

func newHTTP3Transport(ctx context.Context, dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config, keepAlivePeriod time.Duration) http.RoundTripper {
	if keepAlivePeriod == 0 {
		keepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}
	if keepAlivePeriod < 0 {
		keepAlivePeriod = 0
	}
	congestionControlFactory, _ := congestion.NewCongestionControl(options.CongestionController, options.CWND, ntp.TimeFuncFromContext(ctx))
	quicConfig := &quic.Config{
		MaxIdleTimeout: net.ConnIdleTimeout,
		// these two are defaults of quic-go/http3. the default of quic-go (no
		// http3) is different, so it is hardcoded here for clarity.
		// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
		MaxIncomingStreams: -1,
		KeepAlivePeriod:    keepAlivePeriod,
		// the QUIC handshake of Xray-core's client looks like Chrome's
		ChromeParrot: chromeParrot(tlsConfig),
	}
	return &http3.Transport{
		QUICConfig: quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpConn, dErr := dialer.DialContext(ctx, N.NetworkUDP, dest)
			if dErr != nil {
				return nil, dErr
			}
			conn, dErr := qtls.DialEarly(ctx, udpConn, tlsConfig, cfg)
			if dErr != nil {
				_ = udpConn.Close()
				return nil, dErr
			}
			if congestionControlFactory != nil {
				conn.SetCongestionControl(congestionControlFactory(conn))
			}
			return conn, nil
		},
	}
}

// quic-go's Chrome profile refuses a TLS configuration that verifies the server by itself, as
// one with disable_sni does, or that carries a client certificate.
func chromeParrot(tlsConfig tls.Config) bool {
	std, err := tlsConfig.STDConfig()
	return err == nil && std.VerifyConnection == nil && len(std.Certificates) == 0
}
