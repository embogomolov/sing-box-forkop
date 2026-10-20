package link

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// query reads a share link's parameters by name, never in the order the map
// yields them.
type query struct {
	values url.Values
}

func linkQuery(linkURL *url.URL) query {
	return query{values: linkURL.Query()}
}

// get returns the first of the named spellings the link actually carries.
func (q query) get(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(q.values.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

// flag reads a parameter that turns something on. Providers write it as 1, as
// true, or as the bare key.
func (q query) flag(names ...string) bool {
	for _, name := range names {
		values, present := q.values[name]
		if !present {
			continue
		}
		if len(values) == 0 {
			return true
		}
		switch strings.ToLower(strings.TrimSpace(values[0])) {
		case "", "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func (q query) list(names ...string) []string {
	value := q.get(names...)
	if value == "" {
		return nil
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

// serverPort reads the port of a share link, refusing a link without one rather
// than importing a server that dials port zero.
func serverPort(linkURL *url.URL, fallback uint16) (uint16, error) {
	text := linkURL.Port()
	if text == "" {
		if fallback == 0 {
			return 0, E.New("missing server port")
		}
		return fallback, nil
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, E.New("invalid server port: ", text)
	}
	return uint16(port), nil
}

func serverAddress(linkURL *url.URL) (string, error) {
	host := linkURL.Hostname()
	if host == "" {
		return "", E.New("missing server")
	}
	return host, nil
}

// linkTLS reads the TLS parameters a share link carries. always says the
// protocol is TLS by definition - Trojan, TUIC, Hysteria and AnyTLS have no
// plaintext form - in which case the security parameter only selects Reality.
func linkTLS(q query, serverName string, always bool) (*option.OutboundTLSOptions, error) {
	security := strings.ToLower(q.get("security"))
	switch security {
	case "", "none", "tls", "xtls", "reality":
	default:
		return nil, E.New("unsupported security: ", security)
	}
	enabled := always || security == "tls" || security == "xtls" || security == "reality"
	if !enabled {
		return nil, nil
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   q.flag("insecure", "allowInsecure", "allow_insecure", "skip-cert-verify"),
	}
	if name := q.get("sni", "peer", "servername"); name != "" {
		tls.ServerName = name
	}
	if alpn := q.list("alpn"); len(alpn) != 0 {
		tls.ALPN = badoption.Listable[string](alpn)
	}
	reality := security == "reality" || q.get("pbk") != ""
	// Xray-core imitates Chrome when a link names no fingerprint.
	utls, err := subscription.UTLSFingerprint(q.get("fp", "client-fingerprint"), "chrome", reality)
	if err != nil {
		return nil, err
	}
	tls.UTLS = utls
	if reality {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: q.get("pbk", "public-key"),
			ShortID:   q.get("sid", "short-id"),
		}
	}
	return tls, nil
}
