package tls

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// QUICClientOptions drops a uTLS fingerprint, with a warning, from the TLS options of an outbound
// over QUIC: quic-go makes the ClientHello itself, and with one every connection failed (podkop-engine).
func QUICClientOptions(logger logger.Logger, options option.OutboundTLSOptions) option.OutboundTLSOptions {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return options
	}
	logger.Warn("uTLS is not used over QUIC: the fingerprint ", options.UTLS.Fingerprint, " is ignored")
	options.UTLS = nil
	return options
}
