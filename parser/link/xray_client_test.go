package link

import (
	"encoding/base64"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const xrayTestUUID = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"

func vlessOptions(t *testing.T, link string) *option.VLESSOutboundOptions {
	t.Helper()
	outbound, err := ParseSubscriptionLink(link)
	if err != nil {
		t.Fatalf("%s: %v", link, err)
	}
	return outbound.Options.(*option.VLESSOutboundOptions)
}

func fingerprintOf(tls *option.OutboundTLSOptions) string {
	if tls == nil || tls.UTLS == nil || !tls.UTLS.Enabled {
		return ""
	}
	return tls.UTLS.Fingerprint
}

// A transport that speaks one protocol asks for it whatever the link says: panels write
// "h2,http/1.1" for every host, and a server offered both picks HTTP/2, over which no
// WebSocket handshake goes.
func TestLinkTransportAsksForItsOwnALPN(t *testing.T) {
	for _, network := range []string{"ws", "httpupgrade", "grpc", "http"} {
		options := vlessOptions(t, "vless://"+xrayTestUUID+"@example.org:443?type="+network+"&security=tls&sni=example.org&alpn=h2%2Chttp%2F1.1&serviceName=svc&path=%2Fp#n")
		if len(options.TLS.ALPN) != 0 {
			t.Errorf("%s: ALPN %v taken from the link", network, options.TLS.ALPN)
		}
	}
	options := vlessOptions(t, "vless://"+xrayTestUUID+"@example.org:443?type=tcp&security=tls&sni=example.org&alpn=h2%2Chttp%2F1.1#n")
	if len(options.TLS.ALPN) != 2 {
		t.Errorf("tcp: ALPN %v, want the link's", options.TLS.ALPN)
	}
}

// Without a host a WebSocket asks for the server name of TLS, as Xray does: the address of a
// CDN is no name the CDN routes by.
func TestLinkWebSocketHostIsTheServerName(t *testing.T) {
	options := vlessOptions(t, "vless://"+xrayTestUUID+"@192.0.2.1:443?type=ws&security=tls&sni=cdn.example.org&path=%2Fws#n")
	if host := options.Transport.WebsocketOptions.Headers["Host"]; len(host) != 1 || host[0] != "cdn.example.org" {
		t.Fatalf("Host %v, want the server name", host)
	}
	options = vlessOptions(t, "vless://"+xrayTestUUID+"@192.0.2.1:80?type=ws&path=%2Fws#n")
	if host := options.Transport.WebsocketOptions.Headers["Host"]; len(host) != 0 {
		t.Fatalf("Host %v without TLS, want none", host)
	}
}

// The fingerprint is read as Xray reads it: Chrome when a link names none, the same browser
// for a name only Xray knows, no imitation for "unsafe", and REALITY always with a browser.
func TestLinkFingerprintAsXrayReadsIt(t *testing.T) {
	const reality = "&security=reality&sni=www.example.com&pbk=SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ&sid=5a"
	for query, want := range map[string]string{
		"&security=tls&sni=example.org":                    "chrome",
		"&security=tls&sni=example.org&fp=Firefox":         "firefox",
		"&security=tls&sni=example.org&fp=hellochrome_131": "chrome",
		"&security=tls&sni=example.org&fp=unsafe":          "",
		"&security=tls&sni=example.org&fp=nobody-knows":    "",
		reality + "&fp=randomizednoalpn":                   "randomized",
		reality:                                            "chrome",
	} {
		options := vlessOptions(t, "vless://"+xrayTestUUID+"@example.org:443?type=tcp"+query+"#n")
		if fingerprint := fingerprintOf(options.TLS); fingerprint != want {
			t.Errorf("%s: fingerprint %q, want %q", query, fingerprint, want)
		}
	}
	if _, err := ParseSubscriptionLink("vless://" + xrayTestUUID + "@example.org:443?type=tcp" + reality + "&fp=nobody-knows#n"); err == nil {
		t.Error("REALITY with a fingerprint nobody knows was taken")
	}
	outbound, err := ParseSubscriptionLink("hysteria2://secret@example.org:443?sni=example.org#n")
	if err != nil {
		t.Fatal(err)
	}
	if tls := outbound.Options.(*option.Hysteria2OutboundOptions).TLS; tls.UTLS != nil {
		t.Errorf("a QUIC protocol got the fingerprint %v", tls.UTLS)
	}
}

// The HTTP header of the TCP transport is the HTTP transport of sing-box without TLS; with TLS
// that transport would speak HTTP/2.
func TestLinkTCPHTTPHeader(t *testing.T) {
	options := vlessOptions(t, "vless://"+xrayTestUUID+"@example.org:80?type=tcp&headerType=http&host=example.org&path=%2Fa%2C%2Fb#n")
	if options.Transport == nil || options.Transport.Type != C.V2RayTransportTypeHTTP ||
		options.Transport.HTTPOptions.Path != "/a" || len(options.Transport.HTTPOptions.Host) != 1 {
		t.Fatalf("transport %+v, want HTTP to the first path", options.Transport)
	}
	payload := `{"v":"2","ps":"n","add":"example.org","port":"80","id":"` + xrayTestUUID + `","aid":"0","net":"tcp","type":"http","host":"example.org","path":"/","tls":""}`
	outbound, err := ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if transport := outbound.Options.(*option.VMessOutboundOptions).Transport; transport == nil || transport.Type != C.V2RayTransportTypeHTTP {
		t.Fatalf("VMess transport %+v, want HTTP", transport)
	}
	if _, err = ParseSubscriptionLink("vless://" + xrayTestUUID + "@example.org:443?type=tcp&headerType=http&security=tls#n"); err == nil {
		t.Fatal("the HTTP header of the TCP transport was taken over TLS")
	}
}

// A VMess cipher other than the two AEAD ones is "auto", as with the client of Xray: its server
// refuses "none", "zero" and the old stream ciphers.
func TestLinkVMessSecurity(t *testing.T) {
	for scy, want := range map[string]string{"none": "auto", "zero": "auto", "aes-128-cfb": "auto", "": "auto", "chacha20-poly1305": "chacha20-poly1305", "AES-128-GCM": "aes-128-gcm"} {
		payload := `{"v":"2","ps":"n","add":"example.org","port":"443","id":"` + xrayTestUUID + `","aid":"0","scy":"` + scy + `","net":"tcp","tls":"tls"}`
		outbound, err := ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
		if err != nil {
			t.Fatal(err)
		}
		if security := outbound.Options.(*option.VMessOutboundOptions).Security; security != want {
			t.Errorf("scy %q: security %q, want %q", scy, security, want)
		}
	}
}

// Trojan is TLS unless its link says otherwise.
func TestLinkTrojanSecurityNone(t *testing.T) {
	outbound, err := ParseSubscriptionLink("trojan://secret@example.org:443?security=none#n")
	if err != nil {
		t.Fatal(err)
	}
	if tls := outbound.Options.(*option.TrojanOutboundOptions).TLS; tls != nil {
		t.Fatalf("TLS %+v, want none", tls)
	}
}

// A link may say how to reach its server, not which file of this router to read.
func TestLinkShadowsocksPluginCertificateFile(t *testing.T) {
	if _, err := ParseSubscriptionLink("ss://YWVzLTI1Ni1nY206cGFzcw==@example.org:443?plugin=v2ray-plugin%3Btls%3Bcert%3D%2Fetc%2Fshadow#n"); err == nil {
		t.Fatal("a plugin option naming a local file was taken")
	}
}
