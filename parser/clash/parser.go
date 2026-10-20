package clash

import (
	"context"
	"encoding/json"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

type proxyOptions interface {
	Build() (any, error)
}

// proxyTypes maps a Clash proxy type onto the sing-box outbound that speaks the
// same protocol. A type Clash knows and sing-box does not is refused for that
// one node; nothing else in the subscription is affected.
func proxyTypes(proxyType string) (string, proxyOptions, bool) {
	switch proxyType {
	case "ss", "shadowsocks":
		return C.TypeShadowsocks, &shadowsocksOptions{}, true
	case "vmess":
		return C.TypeVMess, &vmessOptions{}, true
	case "vless":
		return C.TypeVLESS, &vlessOptions{}, true
	case "trojan":
		return C.TypeTrojan, &trojanOptions{}, true
	case "hysteria":
		return C.TypeHysteria, &hysteriaOptions{}, true
	case "hysteria2", "hy2":
		return C.TypeHysteria2, &hysteria2Options{}, true
	case "tuic":
		return C.TypeTUIC, &tuicOptions{}, true
	case "anytls":
		return C.TypeAnyTLS, &anyTLSOptions{}, true
	case "snell":
		return C.TypeSnell, &snellOptions{}, true
	case "mieru":
		return C.TypeMieru, &mieruOptions{}, true
	case "socks5":
		return C.TypeSOCKS, &socksOptions{}, true
	case "http":
		return C.TypeHTTP, &httpOptions{}, true
	case "ssh":
		return C.TypeSSH, &sshOptions{}, true
	}
	return "", nil, false
}

// removedTypes are the protocols Clash still speaks and sing-box does not, so
// the reason a node is left out names where the protocol went rather than
// reading as a gap in this parser.
var removedTypes = map[string]string{
	"ssr":          "ShadowsocksR was removed from sing-box in 1.6.0",
	"shadowsocksr": "ShadowsocksR was removed from sing-box in 1.6.0",
	"shadowquic":   "ShadowQUIC has no sing-box equivalent",
	"gost-relay":   "the GOST relay has no sing-box equivalent",
	"zerotier":     "ZeroTier has no sing-box equivalent",
	"wireguard":    "the WireGuard outbound was replaced by an endpoint, which a provider cannot carry",
}

// plumbingTypes are the Clash entries that are not servers at all. Dialling
// through direct is dialling directly, which sing-box writes as no detour;
// dialling through the rest leaves the caller with nothing.
var plumbingTypes = map[string]bool{
	"direct": true, "dns": true, "reject": true, "reject-drop": true,
	"pass": true, "compatible": true, "rematch": true,
}

func ParseClashSubscription(_ context.Context, content string) (subscription.Result, error) {
	var document struct {
		Proxies *[]yaml.Node `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		// YAML is read as a whole, so one malformed proxy (usually an unquoted IPv6 address in a name)
		// breaks the document; a configuration that plainly is Clash's gets the line that broke.
		if !looksLikeClash(content) {
			return subscription.Result{}, subscription.ErrUnrecognized
		}
		return subscription.Result{}, E.Cause(err, "invalid Clash configuration")
	}
	if document.Proxies == nil {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	collector := subscription.NewCollector("Clash")
	for index := range *document.Proxies {
		node := &(*document.Proxies)[index]
		proxyContent, err := proxyContent(node)
		if err != nil {
			collector.Skip("", collector.Label(index, ""), err)
			continue
		}
		var identity struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		_ = json.Unmarshal(proxyContent, &identity)
		label := collector.Label(index, identity.Name)
		proxyType := strings.ToLower(strings.TrimSpace(identity.Type))
		if plumbingTypes[proxyType] {
			if proxyType == "direct" {
				collector.Direct(identity.Name)
			} else {
				collector.Discard(identity.Name)
			}
			continue
		}
		if reason, removed := removedTypes[proxyType]; removed {
			collector.Skip(identity.Name, label, E.New(reason))
			continue
		}
		outboundType, options, supported := proxyTypes(proxyType)
		if !supported {
			collector.Skip(identity.Name, label, E.New("unsupported proxy type: ", identity.Type))
			continue
		}
		if err = decodeProxy(proxyContent, options); err != nil {
			collector.Skip(identity.Name, label, err)
			continue
		}
		built, err := options.Build()
		if err != nil {
			collector.Skip(identity.Name, label, err)
			continue
		}
		collector.Add(option.Outbound{
			Type:    outboundType,
			Tag:     identity.Name,
			Options: built,
		})
	}
	return collector.Result(), nil
}

// looksLikeClash reports whether the content declares proxies the way a Clash
// configuration does, which is enough to name the format when the document is
// too broken to be read.
func looksLikeClash(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "proxies:") {
			return true
		}
	}
	return false
}
