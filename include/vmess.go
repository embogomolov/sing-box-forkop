//go:build with_vmess

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/vmess"
)

func registerVMessInbound(registry *inbound.Registry) {
	vmess.RegisterInbound(registry)
}

func registerVMessOutbound(registry *outbound.Registry) {
	vmess.RegisterOutbound(registry)
}
