package clash

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
)

func parse(t *testing.T, content string) subscription.Result {
	t.Helper()
	result, err := ParseClashSubscription(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestClashKeepsServersCarryingOptionsItDoesNotModel(t *testing.T) {
	// Every one of these is written by a real generator and ignored by Clash
	// itself: a certificate pin, a counter left over from a speed test, an
	// option that belongs to another protocol, and the underscore spelling.
	result := parse(t, `
proxies:
  - name: lenient
    type: ss
    server: ss.example.test
    port: 8388
    cipher: aes-256-gcm
    password: secret-value
    skip_cert_verify: true
    fingerprint: 0a1b2c
    delay: 128
    benchmark: { latency: 40 }
`)
	if len(result.Outbounds) != 1 || len(result.Skipped) != 0 {
		t.Fatalf("unmodelled options lost the server: %d imported, skipped %v", len(result.Outbounds), result.Skipped)
	}
	options := result.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if options.Method != "aes-256-gcm" || options.Password != "secret-value" {
		t.Fatalf("Shadowsocks options = %#v", options)
	}
}

func TestClashIgnoresOptionsBelongingToAnotherTransport(t *testing.T) {
	// A generator that writes out every transport block it knows still describes
	// one way of connecting, and Clash reads only the one the network names.
	result := parse(t, `
proxies:
  - name: websocket
    type: vless
    server: ws.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    network: ws
    ws-opts: { path: /ws, headers: { Host: ws.example.test } }
    grpc-opts: { grpc-service-name: leftover }
    h2-opts: { path: /leftover }
    xhttp-opts: { host: leftover.example.test }
`)
	if len(result.Outbounds) != 1 {
		t.Fatalf("unused transport options lost the server: %v", result.Skipped)
	}
	transport := result.Outbounds[0].Options.(*option.VLESSOutboundOptions).Transport
	if transport.Type != C.V2RayTransportTypeWebsocket || transport.WebsocketOptions.Path != "/ws" {
		t.Fatalf("transport = %#v", transport)
	}
}

func TestClashReadsXHTTPOptionsAsXrayWouldSpellThem(t *testing.T) {
	result := parse(t, `
proxies:
  - name: xhttp
    type: vless
    server: xhttp.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    network: xhttp
    xhttp-opts:
      host: cdn.example.test
      path: /xhttp
      mode: packet-up
      x-padding-bytes: 200-400
      x-padding-key: pad
      x-padding-placement: header
      x-padding-method: tokenish
      uplink-http-method: GET
      session-placement: cookie
      session-key: sid
      seq-placement: header
      seq-key: seq
      session-length: 8-16
      sc-max-each-post-bytes: 1000
      reuse-settings:
        max-concurrency: 2-4
        h-keep-alive-period: 12
`)
	if len(result.Outbounds) != 1 {
		t.Fatalf("XHTTP node was lost: %v", result.Skipped)
	}
	xhttp := result.Outbounds[0].Options.(*option.VLESSOutboundOptions).Transport.XHTTPOptions
	if xhttp.Mode != "packet-up" || xhttp.Host != "cdn.example.test" || xhttp.Path != "/xhttp" ||
		xhttp.XPaddingBytes.From != 200 || xhttp.XPaddingKey != "pad" || xhttp.XPaddingPlacement != "header" ||
		xhttp.XPaddingMethod != "tokenish" || xhttp.UplinkHTTPMethod != "GET" ||
		xhttp.SessionPlacement != "cookie" || xhttp.SessionKey != "sid" ||
		xhttp.SeqPlacement != "header" || xhttp.SeqKey != "seq" || xhttp.SessionIDLength.From != 8 ||
		xhttp.ScMaxEachPostBytes == nil || xhttp.ScMaxEachPostBytes.To != 1000 ||
		xhttp.Xmux == nil || xhttp.Xmux.MaxConcurrency.From != 2 || xhttp.Xmux.HKeepAlivePeriod != 12 {
		t.Fatalf("XHTTP options were lost: %#v", xhttp)
	}
}

func TestClashXHTTPWithoutPaddingKeepsTheDefaultRange(t *testing.T) {
	// Xray reads an unset padding range as its default, and most nodes leave it out.
	result := parse(t, `
proxies:
  - name: plain
    type: vless
    server: xhttp.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    network: xhttp
    xhttp-opts: { host: cdn.example.test, path: /xhttp }
`)
	if len(result.Outbounds) != 1 {
		t.Fatalf("an XHTTP node without a padding range was lost: %v", result.Skipped)
	}
	padding := result.Outbounds[0].Options.(*option.VLESSOutboundOptions).Transport.XHTTPOptions.XPaddingBytes
	if padding.From != 100 || padding.To != 1000 {
		t.Fatalf("padding range = %s, want 100-1000", padding.String())
	}
}

func TestClashRefusesXHTTPSettingsSingBoxCannotDial(t *testing.T) {
	// The GET uplink only exists in packet-up mode; an XHTTP node that could
	// only be built wrong is reported here rather than failing later.
	result := parse(t, `
proxies:
  - name: broken
    type: vless
    server: xhttp.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    network: xhttp
    xhttp-opts: { mode: stream-up, uplink-http-method: GET }
  - name: valid
    type: socks5
    server: socks.example.test
    port: 1080
`)
	if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "valid" {
		t.Fatalf("the broken node survived or its sibling was lost: %v", result.Outbounds)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason.Error(), "packet-up") {
		t.Fatalf("skipped = %v", result.Skipped)
	}
}

func TestClashReportsSkippedServersWithoutTheirSecrets(t *testing.T) {
	result := parse(t, `
proxies:
  - { name: lossy, type: tuic, server: bad.example.test, port: 443, token: private-value }
  - { name: valid, type: socks5, server: valid.example.test, port: 1080 }
`)
	if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "valid" {
		t.Fatalf("the refused node survived or its sibling was lost: %v", result.Outbounds)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("skipped = %v", result.Skipped)
	}
	report := result.Skipped[0].Label + ": " + result.Skipped[0].Reason.Error()
	if !strings.Contains(report, "lossy") {
		t.Fatalf("the report does not name the node: %s", report)
	}
	if strings.Contains(report, "private-value") || strings.Contains(report, "bad.example.test") {
		t.Fatalf("the report leaked the node's address or credentials: %s", report)
	}
}

func TestClashShadowsocksPluginArguments(t *testing.T) {
	result := parse(t, `
proxies:
  - name: obfs
    type: ss
    server: ss.example.test
    port: 8388
    cipher: aes-256-gcm
    password: secret
    plugin: obfs
    plugin-opts: { mode: tls, host: bing.com }
  - name: v2ray-plugin
    type: ss
    server: ss2.example.test
    port: 8388
    cipher: aes-256-gcm
    password: secret
    plugin: v2ray-plugin
    plugin-opts: { mode: websocket, host: cdn.example.test, path: /ws, tls: false, mux: false }
  - name: shadow-tls
    type: ss
    server: ss3.example.test
    port: 8388
    cipher: aes-256-gcm
    password: secret
    plugin: shadow-tls
    plugin-opts: { host: bing.com, password: secret }
`)
	if len(result.Outbounds) != 2 {
		t.Fatalf("imported %d servers, want 2: %v", len(result.Outbounds), result.Skipped)
	}
	obfs := result.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if obfs.Plugin != "obfs-local" || obfs.PluginOptions != "obfs=tls;obfs-host=bing.com" {
		t.Fatalf("obfs arguments = %q %q", obfs.Plugin, obfs.PluginOptions)
	}
	// The plugin reads tls as a flag, so writing it out as tls=false would turn
	// TLS on for a server that does not speak it.
	v2ray := result.Outbounds[1].Options.(*option.ShadowsocksOutboundOptions)
	if strings.Contains(v2ray.PluginOptions, "tls") {
		t.Fatalf("a disabled TLS flag was written out: %q", v2ray.PluginOptions)
	}
	if v2ray.PluginOptions != "mode=websocket;host=cdn.example.test;path=/ws;mux=0" {
		t.Fatalf("v2ray-plugin arguments = %q", v2ray.PluginOptions)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason.Error(), "shadow-tls") {
		t.Fatalf("an unsupported plugin was not reported: %v", result.Skipped)
	}
}

func TestClashRecognisesOnlyItsOwnFormat(t *testing.T) {
	for name, content := range map[string]string{
		"sing-box configuration": `{"outbounds": [{"type": "socks"}]}`,
		"a list of links":        "vless://uuid@example.test:443#node\n",
		"not a document":         "\x00\x01\x02",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClashSubscription(context.Background(), content); err != subscription.ErrUnrecognized {
				t.Fatalf("err = %v, want ErrUnrecognized", err)
			}
		})
	}
}

func TestClashReportsADocumentItCannotRead(t *testing.T) {
	_, err := ParseClashSubscription(context.Background(),
		"proxies:\n- {name: \"broken\"2001:bc8::2\"-052\", server: a.example.test}\n")
	if err == nil || err == subscription.ErrUnrecognized {
		t.Fatalf("a broken Clash configuration was reported as %v", err)
	}
	if !strings.Contains(err.Error(), "Clash") {
		t.Fatalf("the report does not name the format: %v", err)
	}
}

func TestClashQUICServersDropTheClientFingerprint(t *testing.T) {
	// There is no uTLS inside QUIC: sing-box refuses it, so a fingerprint on a Hysteria node is dropped.
	result := parse(t, `
proxies:
  - name: hy2
    type: hysteria2
    server: hy2.example.test
    port: 443
    password: secret
    sni: hy2.example.test
    client-fingerprint: firefox
    alpn: [h3]
  - name: tuic
    type: tuic
    server: tuic.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    password: secret
    sni: tuic.example.test
    client-fingerprint: chrome
`)
	if len(result.Outbounds) != 2 {
		t.Fatalf("imported %d servers: %v", len(result.Outbounds), result.Skipped)
	}
	hysteria := result.Outbounds[0].Options.(*option.Hysteria2OutboundOptions)
	if hysteria.TLS == nil || hysteria.TLS.UTLS != nil {
		t.Fatalf("Hysteria 2 kept a client fingerprint: %#v", hysteria.TLS)
	}
	if len(hysteria.TLS.ALPN) != 1 || hysteria.TLS.ALPN[0] != "h3" {
		t.Fatalf("the rest of the TLS block was lost: %#v", hysteria.TLS)
	}
	if tuic := result.Outbounds[1].Options.(*option.TUICOutboundOptions); tuic.TLS.UTLS != nil {
		t.Fatalf("TUIC kept a client fingerprint: %#v", tuic.TLS)
	}
}

func TestClashReportsInvalidValuesInsteadOfPanicking(t *testing.T) {
	result := parse(t, `
proxies:
  - {name: hop, type: hysteria2, server: h.example.test, port: 443, ports: 20000-30000, hop-interval: 30-10, password: secret}
  - {name: mtu, type: mieru, server: m.example.test, port: 443, username: alice, password: secret, transport: TCP, mtu: 70000}
  - {name: good, type: ss, server: ss.example.test, port: 8388, cipher: aes-256-gcm, password: secret}
`)
	if len(result.Outbounds) != 1 || len(result.Skipped) != 2 {
		t.Fatalf("invalid values were not reported as skipped servers: %d imported, skipped %v", len(result.Outbounds), result.Skipped)
	}
}

func TestClashECHConfigBecomesThePEMBlockSingBoxReads(t *testing.T) {
	list := []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	result := parse(t, `
proxies:
  - name: ech
    type: vless
    server: ech.example.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    ech-opts: {enable: true, config: `+base64.StdEncoding.EncodeToString(list)+`}
`)
	if len(result.Outbounds) != 1 {
		t.Fatalf("the ECH server was skipped: %v", result.Skipped)
	}
	ech := result.Outbounds[0].Options.(*option.VLESSOutboundOptions).TLS.ECH
	block, rest := pem.Decode([]byte(strings.Join(ech.Config, "\n")))
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) != 0 || !bytes.Equal(block.Bytes, list) {
		t.Fatalf("ECH config is not the PEM block sing-box reads: %q", ech.Config)
	}
}
