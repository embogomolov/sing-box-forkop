//go:build !with_quic

package xhttp

import (
	"context"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type h3Server struct{}

func newH3Server(ctx context.Context, options *option.V2RayXHTTPOptions, server *Server) (*h3Server, error) {
	return nil, C.ErrQUICNotIncluded
}

func (h *h3Server) serve(s *Server, listener net.PacketConn) error {
	return C.ErrQUICNotIncluded
}

func (h *h3Server) close() error {
	return nil
}
