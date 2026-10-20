package subscription

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// The fingerprints sing-box knows by these names (common/tls/utls_client.go).
var utlsFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true, "qq": true, "ios": true, "android": true,
	"random": true, "randomized": true,
	"chrome_psk": true, "chrome_psk_shuffle": true, "chrome_padding_psk_shuffle": true, "chrome_pq": true, "chrome_pq_psk": true,
}

// The fingerprints only Xray-core knows by name (transport/internet/tls/tls.go), by browser.
var xrayFingerprints = []struct{ prefix, fingerprint string }{
	{"hellochrome_", "chrome"},
	{"hellofirefox_", "firefox"},
	{"hellosafari_", "safari"},
	{"helloios_", "ios"},
	{"helloedge_", "edge"},
	{"hello360_", "360"},
	{"helloqq_", "qq"},
	{"helloandroid_", "android"},
	{"hellorandomized", "randomized"},
	{"randomizednoalpn", "randomized"},
}

// UTLSFingerprint reads a client fingerprint as Xray-core does: fallback when there is none and
// no imitation for "unsafe", "none" or an unknown name, except under REALITY, which needs one.
func UTLSFingerprint(name string, fallback string, reality bool) (*option.OutboundUTLSOptions, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = fallback
	}
	switch {
	case name == "":
	case utlsFingerprints[name]:
		return &option.OutboundUTLSOptions{Enabled: true, Fingerprint: name}, nil
	case name == "unsafe" || name == "hellogolang" || name == "none":
	default:
		for _, known := range xrayFingerprints {
			if strings.HasPrefix(name, known.prefix) {
				return &option.OutboundUTLSOptions{Enabled: true, Fingerprint: known.fingerprint}, nil
			}
		}
		if reality {
			return nil, E.New("unsupported fingerprint ", name, ", which REALITY needs")
		}
		return nil, nil
	}
	if reality {
		// REALITY passes for the site it borrows only with a browser's hello
		return &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}, nil
	}
	return nil, nil
}

// VMessSecurity reads a VMess cipher as the client of Xray-core does: what is not one of the two
// AEAD ciphers is "auto", since its server refuses "none", "zero" and the stream ciphers.
func VMessSecurity(security string) string {
	switch security = strings.ToLower(strings.TrimSpace(security)); security {
	case "aes-128-gcm", "chacha20-poly1305":
		return security
	default:
		return "auto"
	}
}
