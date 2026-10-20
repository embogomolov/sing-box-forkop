//go:build with_quic

package xhttp

import (
	"context"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/congestion"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/ntp"
)

type h3Server struct {
	quicConfig  *quic.Config
	http3Server *http3.Server
}

func newH3Server(ctx context.Context, options *option.V2RayXHTTPOptions, server *Server) (*h3Server, error) {
	congestionControlFactory, err := congestion.NewCongestionControl(options.CongestionController, options.CWND, ntp.TimeFuncFromContext(ctx))
	if err != nil {
		return nil, err
	}
	return &h3Server{
		quicConfig: &quic.Config{
			DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
		},
		http3Server: &http3.Server{
			Handler: server,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				if congestionControlFactory != nil {
					conn.SetCongestionControl(congestionControlFactory(conn))
				}
				return log.ContextWithNewID(ctx)
			},
		},
	}, nil
}

func (h *h3Server) serve(s *Server, listener net.PacketConn) error {
	quicListener, err := qtls.ListenEarly(listener, s.tlsConfig, h.quicConfig)
	if err != nil {
		return err
	}
	s.localAddr = quicListener.Addr()
	return h.http3Server.ServeListener(quicListener)
}

func (h *h3Server) close() error {
	if h == nil {
		return nil
	}
	return common.Close(h.http3Server)
}
