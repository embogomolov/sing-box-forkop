package link

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/sagernet/quic-go/quicvarint"
)

// A TrustTunnel deep link is tt://? and the endpoint's settings as tag-length-value
// fields in base64url without padding, as TrustTunnel's DEEP_LINK.md defines it in
// format version 2. The fields are written in the order of TrustTunnel's own encoder,
// so a link written here is the one the endpoint exports for the same settings.
const trustTunnelLinkVersion = 2

const (
	trustTunnelFieldVersion uint64 = iota
	trustTunnelFieldHostname
	trustTunnelFieldAddress
	trustTunnelFieldCustomSNI
	trustTunnelFieldHasIPv6
	trustTunnelFieldUsername
	trustTunnelFieldPassword
	trustTunnelFieldSkipVerification
	trustTunnelFieldCertificate
	trustTunnelFieldUpstreamProtocol
	trustTunnelFieldAntiDPI
	trustTunnelFieldClientRandomPrefix
	trustTunnelFieldName
	trustTunnelFieldDNSUpstreams
	trustTunnelFieldSubscriptionURL
	trustTunnelFieldClientRandomAuthKey
)

const (
	trustTunnelProtocolHTTP2 = 1
	trustTunnelProtocolHTTP3 = 2
)

type trustTunnelLink struct {
	hostname            string
	addresses           []string
	customSNI           string
	username            string
	password            string
	skipVerification    bool
	certificate         []byte
	http3               bool
	antiDPI             bool
	name                string
	subscriptionURL     string
	clientRandomAuthKey string
}

// parseTrustTunnelLink maps the link onto the trusttunnel outbound. The node dials
// the first address. An endpoint that admits only clients deriving their TLS
// client_random from an auth key refuses this outbound, so such a link is refused
// here; a client_random prefix is not sent, which an endpoint admits unless a rule
// denies it. The DNS upstreams and the IPv6 flag are the official client's own
// settings and have no counterpart on a node.
func parseTrustTunnelLink(link string) (option.Outbound, error) {
	_, rest, _ := strings.Cut(link, "://")
	rest, fragment, _ := strings.Cut(rest, "#")
	encoded, found := strings.CutPrefix(rest, "?")
	if !found {
		return option.Outbound{}, E.New("TrustTunnel link without its settings after tt://?")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return option.Outbound{}, E.Cause(err, "decode TrustTunnel link")
	}
	parsed, err := readTrustTunnelLink(payload)
	if err != nil {
		return option.Outbound{}, E.Cause(err, "read TrustTunnel link")
	}
	if parsed.clientRandomAuthKey != "" {
		return option.Outbound{}, E.New("TrustTunnel link with client_random_auth_key: the endpoint admits only clients that derive their TLS client_random from the key, which sing-box does not do")
	}
	var missing []string
	for _, field := range []struct {
		name  string
		empty bool
	}{
		{"hostname", parsed.hostname == ""},
		{"address", len(parsed.addresses) == 0},
		{"username", parsed.username == ""},
		{"password", parsed.password == ""},
	} {
		if field.empty {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		if parsed.subscriptionURL != "" {
			return option.Outbound{}, E.New("TrustTunnel link that only names a subscription, without a server of its own")
		}
		return option.Outbound{}, E.New("TrustTunnel link without ", strings.Join(missing, ", "))
	}
	host, portText, err := net.SplitHostPort(parsed.addresses[0])
	if err != nil {
		return option.Outbound{}, E.Cause(err, "TrustTunnel address ", parsed.addresses[0])
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return option.Outbound{}, E.New("TrustTunnel address ", parsed.addresses[0], ": invalid port")
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: parsed.skipVerification,
		Fragment: parsed.antiDPI && !parsed.http3,
	}
	serverName := parsed.hostname
	if parsed.customSNI != "" {
		serverName = parsed.customSNI
	}
	if serverName != host {
		tlsOptions.ServerName = serverName
	}
	if len(parsed.certificate) > 0 {
		certificates, err := x509.ParseCertificates(parsed.certificate)
		if err != nil {
			return option.Outbound{}, E.Cause(err, "TrustTunnel certificate")
		}
		if parsed.customSNI != "" {
			// sing-box checks the certificate against the SNI, and under a custom
			// SNI the endpoint presents the certificate of its hostname: the key
			// of the endpoint's own certificate is pinned instead.
			publicKey, err := x509.MarshalPKIXPublicKey(certificates[0].PublicKey)
			if err != nil {
				return option.Outbound{}, E.Cause(err, "TrustTunnel certificate")
			}
			keyHash := sha256.Sum256(publicKey)
			tlsOptions.CertificatePublicKeySHA256 = [][]byte{keyHash[:]}
		} else {
			for _, certificate := range certificates {
				block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
				tlsOptions.Certificate = append(tlsOptions.Certificate, strings.Split(strings.TrimSpace(string(block)), "\n")...)
			}
		}
	}
	tag := parsed.name
	if fragment != "" {
		if tag, err = url.PathUnescape(fragment); err != nil {
			tag = fragment
		}
	}
	return option.Outbound{
		Type: C.TypeTrustTunnel,
		Tag:  tag,
		Options: &option.TrustTunnelOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: host, ServerPort: uint16(port)},
			Username:                    parsed.username,
			Password:                    parsed.password,
			QUIC:                        parsed.http3,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
		},
	}, nil
}

func readTrustTunnelLink(payload []byte) (trustTunnelLink, error) {
	var parsed trustTunnelLink
	for len(payload) > 0 {
		field, size, err := quicvarint.Parse(payload)
		if err != nil {
			return parsed, E.Cause(err, "field tag")
		}
		payload = payload[size:]
		length, size, err := quicvarint.Parse(payload)
		if err != nil {
			return parsed, E.Cause(err, "field length")
		}
		payload = payload[size:]
		if length > uint64(len(payload)) {
			return parsed, E.New("field ", field, " is cut short")
		}
		value := payload[:length]
		payload = payload[length:]
		switch field {
		case trustTunnelFieldVersion:
			version, err := readTrustTunnelNumber(value)
			if err != nil {
				return parsed, E.Cause(err, "version")
			}
			if version > trustTunnelLinkVersion {
				return parsed, E.New("format version ", version, " is newer than ", trustTunnelLinkVersion)
			}
		case trustTunnelFieldHostname:
			parsed.hostname = string(value)
		case trustTunnelFieldAddress:
			parsed.addresses = append(parsed.addresses, string(value))
		case trustTunnelFieldCustomSNI:
			parsed.customSNI = string(value)
		case trustTunnelFieldUsername:
			parsed.username = string(value)
		case trustTunnelFieldPassword:
			parsed.password = string(value)
		case trustTunnelFieldSkipVerification:
			if parsed.skipVerification, err = readTrustTunnelBool(value); err != nil {
				return parsed, E.Cause(err, "skip_verification")
			}
		case trustTunnelFieldCertificate:
			parsed.certificate = value
		case trustTunnelFieldUpstreamProtocol:
			protocol, err := readTrustTunnelNumber(value)
			if err != nil {
				return parsed, E.Cause(err, "upstream_protocol")
			}
			switch protocol {
			case trustTunnelProtocolHTTP2:
				parsed.http3 = false
			case trustTunnelProtocolHTTP3:
				parsed.http3 = true
			default:
				return parsed, E.New("unknown upstream_protocol ", protocol)
			}
		case trustTunnelFieldAntiDPI:
			if parsed.antiDPI, err = readTrustTunnelBool(value); err != nil {
				return parsed, E.Cause(err, "anti_dpi")
			}
		case trustTunnelFieldName:
			parsed.name = string(value)
		case trustTunnelFieldSubscriptionURL:
			parsed.subscriptionURL = string(value)
		case trustTunnelFieldClientRandomAuthKey:
			parsed.clientRandomAuthKey = string(value)
		}
	}
	return parsed, nil
}

func readTrustTunnelNumber(value []byte) (uint64, error) {
	number, size, err := quicvarint.Parse(value)
	if err != nil {
		return 0, err
	}
	if size != len(value) {
		return 0, E.New("malformed number")
	}
	return number, nil
}

func readTrustTunnelBool(value []byte) (bool, error) {
	if len(value) != 1 || value[0] > 1 {
		return false, E.New("malformed flag")
	}
	return value[0] == 1, nil
}

func generateTrustTunnelLink(outbound option.Outbound) (string, error) {
	options, ok := outbound.Options.(*option.TrustTunnelOutboundOptions)
	if !ok {
		return "", E.New("invalid TrustTunnel outbound options")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return "", E.New("TrustTunnel requires TLS")
	}
	hostname := options.TLS.ServerName
	if hostname == "" {
		hostname = options.Server
	}
	var certificate []byte
	rest := []byte(strings.Join(options.TLS.Certificate, "\n"))
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certificate = append(certificate, block.Bytes...)
		}
	}
	payload := appendTrustTunnelField(nil, trustTunnelFieldVersion, quicvarint.Append(nil, trustTunnelLinkVersion))
	payload = appendTrustTunnelField(payload, trustTunnelFieldHostname, []byte(hostname))
	payload = appendTrustTunnelField(payload, trustTunnelFieldUsername, []byte(options.Username))
	payload = appendTrustTunnelField(payload, trustTunnelFieldPassword, []byte(options.Password))
	payload = appendTrustTunnelField(payload, trustTunnelFieldAddress, []byte(net.JoinHostPort(options.Server, strconv.Itoa(int(options.ServerPort)))))
	if options.TLS.Insecure {
		payload = appendTrustTunnelField(payload, trustTunnelFieldSkipVerification, []byte{1})
	}
	if options.TLS.Fragment {
		payload = appendTrustTunnelField(payload, trustTunnelFieldAntiDPI, []byte{1})
	}
	if len(certificate) > 0 {
		payload = appendTrustTunnelField(payload, trustTunnelFieldCertificate, certificate)
	}
	if options.QUIC {
		payload = appendTrustTunnelField(payload, trustTunnelFieldUpstreamProtocol, quicvarint.Append(nil, trustTunnelProtocolHTTP3))
	}
	if outbound.Tag != "" {
		payload = appendTrustTunnelField(payload, trustTunnelFieldName, []byte(outbound.Tag))
	}
	return "tt://?" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func appendTrustTunnelField(payload []byte, field uint64, value []byte) []byte {
	payload = quicvarint.Append(payload, field)
	payload = quicvarint.Append(payload, uint64(len(value)))
	return append(payload, value...)
}
