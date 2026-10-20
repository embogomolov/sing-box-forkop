//go:build !with_shadowtls

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerShadowTLSInbound(registry *inbound.Registry) {
	inbound.Register[option.ShadowTLSInboundOptions](registry, C.TypeShadowTLS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowTLSInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`ShadowTLS is not included in this build, rebuild with -tags with_shadowtls`)
	})
}

func registerShadowTLSOutbound(registry *outbound.Registry) {
	outbound.Register[option.ShadowTLSOutboundOptions](registry, C.TypeShadowTLS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowTLSOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`ShadowTLS is not included in this build, rebuild with -tags with_shadowtls`)
	})
}
