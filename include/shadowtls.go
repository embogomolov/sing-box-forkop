//go:build with_shadowtls

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/shadowtls"
)

func registerShadowTLSInbound(registry *inbound.Registry) {
	shadowtls.RegisterInbound(registry)
}

func registerShadowTLSOutbound(registry *outbound.Registry) {
	shadowtls.RegisterOutbound(registry)
}
