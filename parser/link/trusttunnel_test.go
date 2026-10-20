package link

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// The links come from TrustTunnel's own encoder, scripts/config_to_deeplink.py of
// TrustTunnel/TrustTunnel, fed with the settings each test names.
const (
	trustTunnelMinimalLink = "tt://?AAECAQ92cG4uZXhhbXBsZS5jb20FBWFsaWNlBglzZWNyZXQxMjMCCzEuMi4zLjQ6NDQz"
	trustTunnelFullLink    = "tt://?AAECARZzZWN1cmUudnBuLmV4YW1wbGUuY29tBQxwcmVtaXVtX3VzZXIGFHZlcnlfc2VjcmV0X3Bhc3N3b3JkAhAxOTIuMTY4LjEuMTo4NDQzAgwxMC4wLjAuMTo0NDMLCWEwYjAvZjBmMAMPY2RuLmV4YW1wbGUub3JnBAEACgEBCQECDAZPZmZpY2UNDg10bHM6Ly8xLjEuMS4x"
	trustTunnelCertLink    = "tt://?AAECAQ92cG4uZXhhbXBsZS5jb20FA2JvYgYJcEBzczp3L3JkAhFbMjAwMTpkYjg6OjFdOjQ0MwoBAQhBqzCCAacwggFNoAMCAQICFHOv5TrL5qeepw8EybZ-5ukOcKOaMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD3Zwbi5leGFtcGxlLmNvbTAgFw0yNjEwMjAwNzUxMzhaGA8yMTI2MDkyNjA3NTEzOFowGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhGFFLgDaOKtrPYZ8xRPadekJvHgcgNzp_aaD20Fka1P5lrIudB7a3AoiP7OYmueU4bmGAU6i-sK23gMcP8Y53KNvMG0wHQYDVR0OBBYEFBokiAwSxGMK5UTzQ9usZC1xPCQnMB8GA1UdIwQYMBaAFBokiAwSxGMK5UTzQ9usZC1xPCQnMA8GA1UdEwEB_wQFMAMBAf8wGgYDVR0RBBMwEYIPdnBuLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIQD_aiBy_xyLnqtTk8Uz_1a-bNHFcdo5iFHtgFm9epIi7AIgXM7bxYnKVxhTowuzsDPDPj6ZBOBDkvh2b6j-CfSXF1kMCUhvbWUgbm9kZQ"
	trustTunnelSNICertLink = "tt://?AAECAQ92cG4uZXhhbXBsZS5jb20FBWNhcm9sBgZzM2NyZXQCEDE5OC41MS4xMDAuNzo0NDMDD2Nkbi5leGFtcGxlLm9yZwhBqzCCAacwggFNoAMCAQICFHOv5TrL5qeepw8EybZ-5ukOcKOaMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD3Zwbi5leGFtcGxlLmNvbTAgFw0yNjEwMjAwNzUxMzhaGA8yMTI2MDkyNjA3NTEzOFowGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhGFFLgDaOKtrPYZ8xRPadekJvHgcgNzp_aaD20Fka1P5lrIudB7a3AoiP7OYmueU4bmGAU6i-sK23gMcP8Y53KNvMG0wHQYDVR0OBBYEFBokiAwSxGMK5UTzQ9usZC1xPCQnMB8GA1UdIwQYMBaAFBokiAwSxGMK5UTzQ9usZC1xPCQnMA8GA1UdEwEB_wQFMAMBAf8wGgYDVR0RBBMwEYIPdnBuLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIQD_aiBy_xyLnqtTk8Uz_1a-bNHFcdo5iFHtgFm9epIi7AIgXM7bxYnKVxhTowuzsDPDPj6ZBOBDkvh2b6j-CfSXF1k"
	trustTunnelSubOnlyLink = "tt://?AAECDi5odHRwczovL3VzZXI6cGFzc0B2cG4uZXhhbXBsZS5jb20vc3Vic2NyaXB0aW9u"
)

// The self-signed certificate of vpn.example.com in trustTunnelCertLink and
// trustTunnelSNICertLink, and the SHA-256 of its public key.
var (
	trustTunnelCertificate = []string{
		"-----BEGIN CERTIFICATE-----",
		"MIIBpzCCAU2gAwIBAgIUc6/lOsvmp56nDwTJtn7m6Q5wo5owCgYIKoZIzj0EAwIw",
		"GjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMCAXDTI2MTAyMDA3NTEzOFoYDzIx",
		"MjYwOTI2MDc1MTM4WjAaMRgwFgYDVQQDDA92cG4uZXhhbXBsZS5jb20wWTATBgcq",
		"hkjOPQIBBggqhkjOPQMBBwNCAASEYUUuANo4q2s9hnzFE9p16Qm8eByA3On9poPb",
		"QWRrU/mWsi50HtrcCiI/s5ia55ThuYYBTqL6wrbeAxw/xjnco28wbTAdBgNVHQ4E",
		"FgQUGiSIDBLEYwrlRPND26xkLXE8JCcwHwYDVR0jBBgwFoAUGiSIDBLEYwrlRPND",
		"26xkLXE8JCcwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgg92cG4uZXhhbXBs",
		"ZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAP9qIHL/HIueq1OTxTP/Vr5s0cVx2jmI",
		"Ue2AWb16kiLsAiBcztvFicpXGFOjC7OwM8M+PpkE4EOS+HZvqP4J9JcXWQ==",
		"-----END CERTIFICATE-----",
	}
	trustTunnelCertificateKeyHash = "buIyZbc+vp6maJYhw/3ovQ8w5F52MjXhKbCqkhQ140M="
)

func TestParseTrustTunnelLinks(t *testing.T) {
	keyHash, err := base64.StdEncoding.DecodeString(trustTunnelCertificateKeyHash)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		link string
		want option.Outbound
	}{
		{"minimal", trustTunnelMinimalLink, option.Outbound{
			Type: C.TypeTrustTunnel,
			Options: &option.TrustTunnelOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 443},
				Username:      "alice",
				Password:      "secret123",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "vpn.example.com",
				}},
			},
		}},
		// The custom SNI is what the node sends; the first of the two addresses is
		// dialled; anti_dpi has nothing to split under QUIC; the IPv6 flag, the DNS
		// upstreams and the client_random prefix are the official client's own.
		{"every field", trustTunnelFullLink, option.Outbound{
			Type: C.TypeTrustTunnel,
			Tag:  "Office",
			Options: &option.TrustTunnelOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "192.168.1.1", ServerPort: 8443},
				Username:      "premium_user",
				Password:      "very_secret_password",
				QUIC:          true,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "cdn.example.org",
				}},
			},
		}},
		{"self-signed certificate", trustTunnelCertLink, option.Outbound{
			Type: C.TypeTrustTunnel,
			Tag:  "Home node",
			Options: &option.TrustTunnelOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "2001:db8::1", ServerPort: 443},
				Username:      "bob",
				Password:      "p@ss:w/rd",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled:     true,
					ServerName:  "vpn.example.com",
					Certificate: trustTunnelCertificate,
					Fragment:    true,
				}},
			},
		}},
		// Under a custom SNI the endpoint presents its hostname's certificate,
		// which sing-box would check against the SNI: the key is pinned instead.
		{"custom SNI with certificate", trustTunnelSNICertLink, option.Outbound{
			Type: C.TypeTrustTunnel,
			Options: &option.TrustTunnelOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "198.51.100.7", ServerPort: 443},
				Username:      "carol",
				Password:      "s3cret",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled:                    true,
					ServerName:                 "cdn.example.org",
					CertificatePublicKeySHA256: badoption.Listable[[]byte]{keyHash},
				}},
			},
		}},
		{"name in the fragment", trustTunnelMinimalLink + "#My%20node", option.Outbound{
			Type: C.TypeTrustTunnel,
			Tag:  "My node",
			Options: &option.TrustTunnelOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 443},
				Username:      "alice",
				Password:      "secret123",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "vpn.example.com",
				}},
			},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(test.link)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(outbound, test.want) {
				t.Fatalf("parsed\n%#v\n%#v\nwant\n%#v\n%#v", outbound, outbound.Options, test.want, test.want.Options)
			}
		})
	}
}

func TestParseTrustTunnelLinkRefusals(t *testing.T) {
	field := func(tag, value string) string {
		return string([]byte{byte(tag[0]), byte(len(value))}) + value
	}
	encode := func(payload string) string {
		return "tt://?" + base64.RawURLEncoding.EncodeToString([]byte(payload))
	}
	server := field("\x01", "vpn.example.com") + field("\x05", "alice") + field("\x06", "secret") + field("\x02", "1.2.3.4:443")
	tests := []struct {
		name string
		link string
		want string
	}{
		{"subscription only", trustTunnelSubOnlyLink, "only names a subscription"},
		{"auth key", encode(field("\x00", "\x02") + server + field("\x0f", "00112233445566778899aabbccddeeff")), "client_random_auth_key"},
		{"newer format", encode(field("\x00", "\x03") + server), "format version 3"},
		{"no password", encode(field("\x01", "vpn.example.com") + field("\x05", "alice") + field("\x02", "1.2.3.4:443")), "without password"},
		{"unknown protocol", encode(server + field("\x09", "\x03")), "unknown upstream_protocol 3"},
		{"malformed flag", encode(server + field("\x07", "\x02")), "skip_verification"},
		{"cut short", encode(server[:len(server)-2]), "cut short"},
		{"address without port", encode(field("\x01", "vpn.example.com") + field("\x05", "alice") + field("\x06", "secret") + field("\x02", "1.2.3.4")), "TrustTunnel address"},
		{"settings in the host", "tt://" + strings.TrimPrefix(trustTunnelMinimalLink, "tt://?"), "after tt://?"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseSubscriptionLink(test.link)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want an error naming %q", err, test.want)
			}
		})
	}
}

// A node the link describes in full comes back as the very link TrustTunnel's
// encoder writes, but for the format version: its links are version 2, these 1.
func TestGenerateTrustTunnelLinkMatchesTheReferenceEncoder(t *testing.T) {
	for _, link := range []string{trustTunnelMinimalLink, trustTunnelCertLink} {
		outbound, err := ParseSubscriptionLink(link)
		if err != nil {
			t.Fatal(err)
		}
		generated, err := GenerateSubscriptionLink(outbound)
		if err != nil {
			t.Fatal(err)
		}
		want := "tt://?AAEB" + strings.TrimPrefix(link, "tt://?AAEC")
		if generated != want {
			t.Fatalf("generated\n%s\nwant\n%s", generated, want)
		}
	}
}

func TestGenerateTrustTunnelLinkRefusesWhatItCannotCarry(t *testing.T) {
	sniPinned, err := ParseSubscriptionLink(trustTunnelSNICertLink)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]option.Outbound{
		"pinned key": sniPinned,
		"uTLS": trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) {
			o.TLS.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
		}),
		"TCP only":    trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) { o.Network = "tcp" }),
		"health":      trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) { o.HealthCheck = true }),
		"QUIC split":  trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) { o.QUIC = true; o.TLS.Fragment = true }),
		"ALPN":        trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) { o.TLS.ALPN = badoption.Listable[string]{"h2"} }),
		"without TLS": trustTunnelOutbound(func(o *option.TrustTunnelOutboundOptions) { o.TLS = nil }),
	}
	for name, outbound := range tests {
		t.Run(name, func(t *testing.T) {
			if link, err := GenerateSubscriptionLink(outbound); err == nil {
				t.Fatalf("generated %s", link)
			}
		})
	}
}

func trustTunnelOutbound(change func(*option.TrustTunnelOutboundOptions)) option.Outbound {
	options := &option.TrustTunnelOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "vpn.example.com", ServerPort: 443},
		Username:      "alice",
		Password:      "secret",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true,
		}},
	}
	change(options)
	return option.Outbound{Type: C.TypeTrustTunnel, Tag: "node", Options: options}
}
