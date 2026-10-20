//go:build !with_tor

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerTorOutbound(registry *outbound.Registry) {
	outbound.Register[option.TorOutboundOptions](registry, C.TypeTor, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TorOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Tor is not included in this build, rebuild with -tags with_tor`)
	})
}
