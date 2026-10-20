package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

// trustTunnelOptions is mihomo's TrustTunnel proxy. Its connection pool settings
// (max-connections, min-streams, max-streams) and the QUIC window settings have no
// counterpart: the sing-box node keeps one session to the endpoint.
type trustTunnelOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	Username             subscription.String `json:"username"`
	Password             subscription.String `json:"password"`
	UDP                  subscription.Bool   `json:"udp"`
	HealthCheck          subscription.Bool   `json:"health-check"`
	QUIC                 subscription.Bool   `json:"quic"`
	CongestionController string              `json:"congestion-controller"`
	NameCertVerify       string              `json:"name-cert-verify"`
}

func (o *trustTunnelOptions) Build() (any, error) {
	if err := o.serverOptions.check(); err != nil {
		return nil, err
	}
	if err := o.tlsOptions.check(); err != nil {
		return nil, err
	}
	if o.Username == "" {
		return nil, E.New("missing username")
	}
	if o.Password == "" {
		return nil, E.New("missing password")
	}
	tls := o.tlsOptions.build(o.Server, true)
	// mihomo checks the certificate against this name, sing-box against the SNI.
	if o.NameCertVerify != "" && o.NameCertVerify != tls.ServerName {
		return nil, E.New("Clash name-cert-verify has no sing-box equivalent")
	}
	congestionControl := o.CongestionController
	switch congestionControl {
	case "", "bbr", "cubic", "reno":
	case "new_reno":
		congestionControl = "reno"
	default:
		return nil, E.New("unsupported congestion-controller: ", congestionControl)
	}
	if o.QUIC.Value() {
		tls = subscription.QUICSecurity(tls)
	}
	return &option.TrustTunnelOutboundOptions{
		DialerOptions:               o.dialerOptions.build(),
		ServerOptions:               o.serverOptions.build(),
		Username:                    string(o.Username),
		Password:                    string(o.Password),
		Network:                     networks(o.UDP),
		QUIC:                        o.QUIC.Value(),
		QUICCongestionControl:       congestionControl,
		HealthCheck:                 o.HealthCheck.Value(),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
	}, nil
}
