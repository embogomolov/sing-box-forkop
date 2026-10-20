package xray

import (
	"context"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
)

func parse(t *testing.T, content string) subscription.Result {
	t.Helper()
	result, err := ParseXraySubscription(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func vless(t *testing.T, result subscription.Result, index int) *option.VLESSOutboundOptions {
	t.Helper()
	if index >= len(result.Outbounds) {
		t.Fatalf("server %d was not imported, got %d: %v", index+1, len(result.Outbounds), result.Skipped)
	}
	options, isVLESS := result.Outbounds[index].Options.(*option.VLESSOutboundOptions)
	if !isVLESS {
		t.Fatalf("server %d is %s", index+1, result.Outbounds[index].Type)
	}
	return options
}

func TestXrayIgnoresTransportSettingsTheStreamDoesNotUse(t *testing.T) {
	// Xray keeps the settings of every transport in one list and reads only the
	// one the network names, so a document that writes them all out - the shape
	// a panel template produces - still describes one way of connecting.
	result := parse(t, `{"outbounds": [{
  "protocol": "vless",
  "tag": "template",
  "settings": {"vnext": [{"address": "ws.example.test", "port": 443, "users": [{"id": "uuid"}]}]},
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "tlsSettings": {"serverName": "ws.example.test"},
    "wsSettings": {"host": "cdn.example.test", "path": "/ws"},
    "tcpSettings": {"header": {"type": "none"}},
    "kcpSettings": {"mtu": 1350, "header": {"type": "srtp"}},
    "grpcSettings": {"serviceName": "leftover"},
    "httpSettings": {"host": ["leftover.example.test"], "path": "/leftover"}
  }
}]}`)
	options := vless(t, result, 0)
	transport := options.Transport
	if transport == nil || transport.Type != C.V2RayTransportTypeWebsocket || transport.WebsocketOptions.Path != "/ws" {
		t.Fatalf("transport = %#v", transport)
	}
	// The independent host field is the one Xray sends; a proxy in front answers a request without a
	// Host header with the wrong site.
	if host := transport.WebsocketOptions.Headers["Host"]; len(host) != 1 || host[0] != "cdn.example.test" {
		t.Fatalf("Host header = %q", transport.WebsocketOptions.Headers)
	}
}

func TestXraySecurityDecidesWhetherThereIsTLS(t *testing.T) {
	// Xray applies TLS only when the security field asks for it and ignores the settings otherwise.
	result := parse(t, `{"outbounds": [
  {
    "protocol": "vless", "tag": "plaintext",
    "settings": {"vnext": [{"address": "plain.example.test", "port": 80, "users": [{"id": "uuid"}]}]},
    "streamSettings": {"network": "tcp", "security": "none", "tlsSettings": {"serverName": "plain.example.test", "alpn": ["h2"]}}
  },
  {
    "protocol": "vless", "tag": "reality",
    "settings": {"vnext": [{"address": "reality.example.test", "port": 443, "users": [{"id": "uuid", "flow": "xtls-rprx-vision"}]}]},
    "streamSettings": {"network": "raw", "security": "reality", "rawSettings": {"header": {"type": "none"}},
      "realitySettings": {"serverName": "www.example.com", "publicKey": "public-key", "shortId": "abcd", "fingerprint": "firefox"}}
  }
]}`)
	if len(result.Outbounds) != 2 {
		t.Fatalf("imported %d servers: %v", len(result.Outbounds), result.Skipped)
	}
	if tls := vless(t, result, 0).TLS; tls != nil {
		t.Fatalf("a server with security none got TLS: %#v", tls)
	}
	// raw is the current spelling of the plain connection, and its settings are
	// written under rawSettings.
	reality := vless(t, result, 1)
	if reality.Transport != nil {
		t.Fatalf("raw got a transport: %#v", reality.Transport)
	}
	if reality.TLS == nil || reality.TLS.Reality == nil || reality.TLS.Reality.PublicKey != "public-key" ||
		reality.TLS.ServerName != "www.example.com" || reality.TLS.UTLS.Fingerprint != "firefox" {
		t.Fatalf("Reality settings = %#v", reality.TLS)
	}
}

func TestXrayChainedOutboundIsADetourEitherWay(t *testing.T) {
	// Xray dials through the named handler whether proxySettings asks for it at
	// the transport layer or not, and both are a detour in sing-box.
	result := parse(t, `{"outbounds": [
  {"protocol": "socks", "tag": "hop", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}},
  {"protocol": "socks", "tag": "protocol-layer", "settings": {"servers": [{"address": "127.0.0.1", "port": 1081}]}, "proxySettings": {"tag": "hop"}},
  {"protocol": "socks", "tag": "transport-layer", "settings": {"servers": [{"address": "127.0.0.1", "port": 1082}]}, "proxySettings": {"tag": "hop", "transportLayer": true}},
  {"protocol": "freedom", "tag": "direct"},
  {"protocol": "socks", "tag": "through-freedom", "settings": {"servers": [{"address": "127.0.0.1", "port": 1083}]}, "streamSettings": {"sockopt": {"dialerProxy": "direct"}}},
  {"protocol": "socks", "tag": "external", "settings": {"servers": [{"address": "127.0.0.1", "port": 1084}]}, "streamSettings": {"sockopt": {"dialerProxy": "user-configured"}}}
]}`)
	if len(result.Outbounds) != 5 {
		t.Fatalf("imported %d servers: %v", len(result.Outbounds), result.Skipped)
	}
	detours := make(map[string]string, len(result.Outbounds))
	for _, outbound := range result.Outbounds {
		detours[outbound.Tag] = outbound.Options.(*option.SOCKSOutboundOptions).Detour
	}
	for tag, want := range map[string]string{
		"protocol-layer":  "hop",
		"transport-layer": "hop",
		"through-freedom": "",
		"external":        "user-configured",
	} {
		if detours[tag] != want {
			t.Errorf("%s detour = %q, want %q", tag, detours[tag], want)
		}
	}
}

func TestXrayPlumbingOutboundsAreNotServers(t *testing.T) {
	// Every document of a per-server subscription carries these beside its server; they are not
	// unsupported protocols.
	result := parse(t, `{"outbounds": [
  {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "a.example.test", "port": 443, "users": [{"id": "uuid"}]}]}},
  {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIP"}},
  {"protocol": "blackhole", "tag": "block", "settings": {"response": {"type": "http"}}},
  {"protocol": "dns", "tag": "dns-out"},
  {"protocol": "socks", "tag": "through-blackhole", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}, "proxySettings": {"tag": "block"}}
]}`)
	if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "proxy" {
		t.Fatalf("imported servers = %v", result.Outbounds)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Label, "through-blackhole") {
		t.Fatalf("skipped = %v", result.Skipped)
	}
}

func TestXrayNamesEachDocumentByItsRemarks(t *testing.T) {
	// A per-server subscription tags the outbound inside every document proxy, so servers take the
	// document remarks instead.
	result := parse(t, `[
  {"remarks": "Sweden", "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "se.example.test", "port": 443, "users": [{"id": "uuid"}]}]}}]},
  {"remarks": "Germany", "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "de.example.test", "port": 443, "users": [{"id": "uuid"}]}]}}]},
  {"outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "unnamed.example.test", "port": 443, "users": [{"id": "uuid"}]}]}}]}
]`)
	want := []string{"Sweden", "Germany", "proxy"}
	if len(result.Outbounds) != len(want) {
		t.Fatalf("imported %d servers: %v", len(result.Outbounds), result.Skipped)
	}
	for index, tag := range want {
		if result.Outbounds[index].Tag != tag {
			t.Fatalf("server %d = %q, want %q", index, result.Outbounds[index].Tag, tag)
		}
	}
}

func TestXrayRefusesWhatItCannotRepresent(t *testing.T) {
	for name, outbound := range map[string]string{
		"unsupported protocol": `{"protocol": "wireguard", "tag": "wg", "settings": {}}`,
		"a masked raw stream": `{"protocol": "vless", "tag": "masked",
			"settings": {"vnext": [{"address": "a.example.test", "port": 443, "users": [{"id": "uuid"}]}]},
			"streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http"}}}}`,
		"an unsupported flow": `{"protocol": "vless", "tag": "flow",
			"settings": {"vnext": [{"address": "a.example.test", "port": 443, "users": [{"id": "uuid", "flow": "xtls-rprx-direct"}]}]}}`,
		"two servers in one outbound": `{"protocol": "vless", "tag": "pair",
			"settings": {"vnext": [{"address": "a.example.test", "port": 443, "users": [{"id": "uuid"}]}, {"address": "b.example.test", "port": 443, "users": [{"id": "uuid"}]}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			result := parse(t, `{"outbounds": [`+outbound+`,
				{"protocol": "socks", "tag": "valid", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}}]}`)
			if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "valid" {
				t.Fatalf("the refused server survived or its sibling was lost: %v", result.Outbounds)
			}
			if len(result.Skipped) != 1 {
				t.Fatalf("skipped = %v", result.Skipped)
			}
		})
	}
}

func TestXrayRecognisesOnlyItsOwnFormat(t *testing.T) {
	for name, content := range map[string]string{
		"sing-box configuration": `{"outbounds": [{"type": "socks", "tag": "box"}]}`,
		"a Clash configuration":  "proxies:\n  - {name: a, type: socks5}\n",
		"a list of links":        "vless://uuid@example.test:443#node\n",
		"an empty document":      `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseXraySubscription(context.Background(), content); err != subscription.ErrUnrecognized {
				t.Fatalf("err = %v, want ErrUnrecognized", err)
			}
		})
	}
}

func TestXrayHysteriaDropsTheClientFingerprint(t *testing.T) {
	// Xray writes a fingerprint into the TLS settings of its Hysteria outbound
	// as well, and sing-box has no uTLS inside a QUIC handshake.
	result := parse(t, `{"outbounds": [{
  "protocol": "hysteria",
  "tag": "proxy",
  "settings": {"address": "hy2.example.test", "port": 9999, "version": 2},
  "streamSettings": {
    "network": "hysteria",
    "security": "tls",
    "hysteriaSettings": {"version": 2, "auth": "secret"},
    "tlsSettings": {"serverName": "hy2.example.test", "fingerprint": "firefox", "alpn": ["h3"]},
    "finalmask": {"quicParams": {"congestion": "bbr"}}
  }
}]}`)
	if len(result.Outbounds) != 1 {
		t.Fatalf("imported %d servers: %v", len(result.Outbounds), result.Skipped)
	}
	options := result.Outbounds[0].Options.(*option.Hysteria2OutboundOptions)
	if options.Password != "secret" || options.ServerPort != 9999 {
		t.Fatalf("the server was read wrong: %#v", options)
	}
	if options.TLS == nil || options.TLS.UTLS != nil {
		t.Fatalf("Hysteria 2 kept a client fingerprint: %#v", options.TLS)
	}
	if len(options.TLS.ALPN) != 1 || options.TLS.ALPN[0] != "h3" {
		t.Fatalf("the rest of the TLS block was lost: %#v", options.TLS)
	}
}
