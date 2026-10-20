//go:build with_anytls

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/anytls"
)

func registerAnyTLSInbound(registry *inbound.Registry) {
	anytls.RegisterInbound(registry)
}

func registerAnyTLSOutbound(registry *outbound.Registry) {
	anytls.RegisterOutbound(registry)
}
