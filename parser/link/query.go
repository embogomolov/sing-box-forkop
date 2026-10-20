package link

import (
	"encoding/base64"
	"encoding/pem"
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

// linkQuery reads the parameters by their names in lower case: clients differ in the case they
// write ("allowInsecure", "allowinsecure"), and a link copied out of HTML has "&amp;" between
// them, a name net/url leaves out for its ";".
func linkQuery(linkURL *url.URL) query {
	values := make(url.Values)
	for _, pair := range strings.Split(linkURL.RawQuery, "&") {
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || name == "" {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			continue
		}
		name = strings.TrimPrefix(strings.ToLower(name), "amp;")
		values[name] = append(values[name], value)
	}
	return query{values: values}
}

// get returns the first of the named spellings the link actually carries.
func (q query) get(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(q.values.Get(strings.ToLower(name))); value != "" {
			return value
		}
	}
	return ""
}

// flag reads a parameter that turns something on. Providers write it as 1, as
// true, or as the bare key.
func (q query) flag(names ...string) bool {
	for _, name := range names {
		values, present := q.values[strings.ToLower(name)]
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

// parseLinkURL parses a link whose user may hold a "/", as a Trojan password in base64 often
// does unescaped: the user is everything up to the last "@" before the parameters.
func parseLinkURL(link string) (*url.URL, error) {
	if scheme, rest, found := strings.Cut(link, "://"); found {
		end := strings.IndexAny(rest, "?#")
		if end < 0 {
			end = len(rest)
		}
		if at := strings.LastIndex(rest[:end], "@"); at >= 0 && strings.Contains(rest[:at], "/") {
			link = scheme + "://" + strings.ReplaceAll(rest[:at], "/", "%2F") + rest[at:]
		}
	}
	return url.Parse(link)
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
	tls.DisableSNI = q.flag("disable_sni", "nosni")
	if certificate := q.get("cert"); strings.HasPrefix(certificate, "-----BEGIN ") {
		// NekoBox and husi carry the certificate to trust in the link itself
		tls.Certificate = strings.Split(strings.ReplaceAll(certificate, "\r\n", "\n"), "\n")
	}
	tls.ECH = linkECH(q.get("ech"))
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

// linkECH reads the "ech" of a link as Xray-core does: the ECH configuration list in base64, or
// where to ask for it, a resolver or a name and a resolver joined with "+". sing-box asks its own
// DNS for the configuration.
func linkECH(value string) *option.OutboundECHOptions {
	// form decoding has made a space of every "+"
	value = strings.ReplaceAll(value, " ", "+")
	if value == "" {
		return nil
	}
	if strings.Contains(value, "://") {
		options := &option.OutboundECHOptions{Enabled: true}
		if name, _, named := strings.Cut(value, "+"); named && !strings.Contains(name, "://") {
			options.QueryServerName = name
		}
		return options
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if list, err := encoding.DecodeString(value); err == nil && len(list) > 0 {
			block := pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: list})
			return &option.OutboundECHOptions{Enabled: true, Config: strings.Split(strings.TrimSpace(string(block)), "\n")}
		}
	}
	return nil
}
