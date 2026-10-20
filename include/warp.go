//go:build with_wireguard

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/warp"
)

func registerWARPEndpoint(registry *endpoint.Registry) {
	warp.RegisterEndpoint(registry)
}
