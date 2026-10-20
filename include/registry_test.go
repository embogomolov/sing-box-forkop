package include

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// A build without a tag registers a stub that names the tag, never leaves the type unknown.
func TestEveryTypeIsRegisteredWhateverTheTags(t *testing.T) {
	t.Parallel()
	require.Subset(t, InboundRegistry().OptionTypes(), []string{
		C.TypeRedirect, C.TypeTProxy, C.TypeDirect, C.TypeSOCKS, C.TypeHTTP, C.TypeMixed,
		C.TypeShadowsocks, C.TypeSnell, C.TypeVMess, C.TypeTrojan, C.TypeNaive, C.TypeShadowTLS,
		C.TypeVLESS, C.TypeAnyTLS, C.TypeMieru, C.TypeTrustTunnel, C.TypeHysteria, C.TypeTUIC,
		C.TypeHysteria2,
	})
	require.Subset(t, OutboundRegistry().OptionTypes(), []string{
		C.TypeDirect, C.TypeBlock, C.TypeFallback, C.TypeSelector, C.TypeURLTest, C.TypeSOCKS,
		C.TypeHTTP, C.TypeShadowsocks, C.TypeSnell, C.TypeVMess, C.TypeTrojan, C.TypeNaive,
		C.TypeTor, C.TypeSSH, C.TypeShadowTLS, C.TypeVLESS, C.TypeMieru, C.TypeAnyTLS,
		C.TypeTrustTunnel, C.TypeParser, C.TypeHysteria, C.TypeTUIC, C.TypeHysteria2,
	})
	require.Subset(t, EndpointRegistry().OptionTypes(), []string{
		C.TypeWireGuard, C.TypeAmneziaWG, C.TypeWARP, C.TypeOpenConnect, C.TypeOpenVPNClient,
		C.TypeOpenVPNServer, C.TypeTailscale,
	})
	require.Subset(t, DNSTransportRegistry().OptionTypes(), []string{
		C.DNSTypeTCP, C.DNSTypeUDP, C.DNSTypeTLS, C.DNSTypeHTTPS, C.DNSTypeQUIC, C.DNSTypeHTTP3,
		C.DNSTypeHosts, C.DNSTypeLocal, C.DNSTypeFakeIP, C.DNSTypeFallback, C.DNSTypeOpenConnect,
		C.DNSTypeOpenVPN, C.DNSTypeTailscale,
	})
}
