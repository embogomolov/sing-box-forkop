// Package xhttp reads the XHTTP transport settings a subscription carries, in Xray's
// streamSettings, a share link's "extra" object and Clash's xhttp-opts. The client settings must
// match the server exactly, or the server answers a different request than the client makes.
package xhttp

import (
	"encoding/json"
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

type _Settings struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Mode    string            `json:"mode"`
	Headers map[string]string `json:"headers"`

	XPaddingBytes     *subscription.Range `json:"xPaddingBytes"`
	XPaddingObfsMode  subscription.Bool   `json:"xPaddingObfsMode"`
	XPaddingKey       string              `json:"xPaddingKey"`
	XPaddingHeader    string              `json:"xPaddingHeader"`
	XPaddingPlacement string              `json:"xPaddingPlacement"`
	XPaddingMethod    string              `json:"xPaddingMethod"`

	UplinkHTTPMethod    string              `json:"uplinkHTTPMethod"`
	UplinkDataPlacement string              `json:"uplinkDataPlacement"`
	UplinkDataKey       string              `json:"uplinkDataKey"`
	UplinkChunkSize     *subscription.Range `json:"uplinkChunkSize"`

	SessionIDPlacement string              `json:"sessionIDPlacement"`
	SessionPlacement   string              `json:"sessionPlacement"`
	SessionIDKey       string              `json:"sessionIDKey"`
	SessionKey         string              `json:"sessionKey"`
	SessionIDTable     string              `json:"sessionIDTable"`
	SessionIDLength    *subscription.Range `json:"sessionIDLength"`

	SeqPlacement string `json:"seqPlacement"`
	SeqKey       string `json:"seqKey"`

	NoGRPCHeader subscription.Bool `json:"noGRPCHeader"`
	NoSSEHeader  subscription.Bool `json:"noSSEHeader"`

	ScMaxEachPostBytes   *subscription.Range `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs *subscription.Range `json:"scMinPostsIntervalMs"`
	ScStreamUpServerSecs *subscription.Range `json:"scStreamUpServerSecs"`
	ScMaxBufferedPosts   subscription.Int    `json:"scMaxBufferedPosts"`
	ScMaxConcurrentPosts subscription.Int    `json:"scMaxConcurrentPosts"`

	ServerMaxHeaderBytes subscription.Int        `json:"serverMaxHeaderBytes"`
	MaxHeaderBytes       subscription.Int        `json:"maxHeaderBytes"`
	CongestionController string                  `json:"congestionController"`
	CWND                 subscription.Int        `json:"cwnd"`
	TrustedXForwardedFor subscription.StringList `json:"trustedXForwardedFor"`

	Xmux             *XmuxSettings   `json:"xmux"`
	DownloadSettings json.RawMessage `json:"downloadSettings"`
	Extra            json.RawMessage `json:"extra"`
}

// Settings is one XHTTP configuration as the subscription wrote it.
type Settings _Settings

// DefaultPaddingBytes is the padding range Xray assumes when none is given;
// sing-box refuses an unset one.
var DefaultPaddingBytes = option.Range[int]{From: 100, To: 1000}

type XmuxSettings struct {
	MaxConcurrency   *subscription.Range `json:"maxConcurrency"`
	MaxConnections   *subscription.Range `json:"maxConnections"`
	CMaxReuseTimes   *subscription.Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes *subscription.Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs *subscription.Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod subscription.Int    `json:"hKeepAlivePeriod"`
}

// UnmarshalJSON applies Xray's rule for "extra": when present it replaces everything else except
// the host, the path and the mode.
func (s *Settings) UnmarshalJSON(content []byte) error {
	if err := json.Unmarshal(content, (*_Settings)(s)); err != nil {
		return err
	}
	if len(s.Extra) == 0 {
		return nil
	}
	extraContent := []byte(s.Extra)
	// A share link carries the same object as a string.
	var encoded string
	if json.Unmarshal(s.Extra, &encoded) == nil {
		extraContent = []byte(encoded)
	}
	var extra Settings
	if err := json.Unmarshal(extraContent, (*_Settings)(&extra)); err != nil {
		return E.Cause(err, "invalid XHTTP extra")
	}
	extra.Host, extra.Path, extra.Mode = s.Host, s.Path, s.Mode
	extra.Extra = nil
	*s = extra
	return nil
}

// LinkSettings reads the XHTTP settings of a share link: the host, the path and
// the mode of the link itself and everything else from its extra object, which
// a link carries verbatim, base64 encoded or as a JSON string.
func LinkSettings(host, path, mode, extra string) (Settings, error) {
	content := strings.TrimSpace(extra)
	var quoted string
	if json.Unmarshal([]byte(content), &quoted) == nil {
		content = strings.TrimSpace(quoted)
	}
	if strings.HasPrefix(content, "%") {
		// escaped twice by some generators
		if unescaped, err := url.QueryUnescape(content); err == nil {
			content = strings.TrimSpace(unescaped)
		}
	}
	if decoded, isEncoded := subscription.DecodeBase64(content); isEncoded {
		content = decoded
	}
	var settings Settings
	if content != "" {
		if err := json.Unmarshal([]byte(content), (*_Settings)(&settings)); err != nil {
			return Settings{}, E.Cause(err, "invalid XHTTP extra")
		}
	}
	settings.Host, settings.Path, settings.Mode, settings.Extra = host, path, mode, nil
	return settings, nil
}

// Download reads the download leg of a transport, its downloadSettings: the server it dials,
// the TLS and the XHTTP settings of its own.
type Download func(content json.RawMessage) (*option.V2RayXHTTPDownloadOptions, error)

// Build renders the settings through sing-box's own decoder, which fills in a server's defaults
// and refuses a combination sing-box cannot dial, so a broken XHTTP node is reported here.
func (s Settings) Build(download Download) (*option.V2RayTransportOptions, error) {
	base, err := s.Base()
	if err != nil {
		return nil, err
	}
	// v2rayA writes the modes with "_"
	options := option.V2RayXHTTPOptions{Mode: strings.ReplaceAll(strings.ToLower(s.Mode), "_", "-"), V2RayXHTTPBaseOptions: base}
	if hasContent(s.DownloadSettings) {
		if download == nil {
			return nil, E.New("XHTTP download settings cannot be represented")
		}
		if options.Download, err = download(s.DownloadSettings); err != nil {
			return nil, E.Cause(err, "invalid XHTTP download settings")
		}
	}
	normalized, err := Normalize(options)
	if err != nil {
		return nil, err
	}
	return &option.V2RayTransportOptions{
		Type:         C.V2RayTransportTypeXHTTP,
		XHTTPOptions: normalized,
	}, nil
}

// Base reads the settings of one leg: all of them but the mode and the download leg.
func (s Settings) Base() (option.V2RayXHTTPBaseOptions, error) {
	base := option.V2RayXHTTPBaseOptions{
		Host:                 s.Host,
		Path:                 s.Path,
		Headers:              s.Headers,
		XPaddingObfsMode:     s.XPaddingObfsMode.Value(),
		XPaddingKey:          s.XPaddingKey,
		XPaddingHeader:       s.XPaddingHeader,
		XPaddingPlacement:    s.XPaddingPlacement,
		XPaddingMethod:       s.XPaddingMethod,
		UplinkHTTPMethod:     s.UplinkHTTPMethod,
		UplinkDataPlacement:  s.UplinkDataPlacement,
		UplinkDataKey:        s.UplinkDataKey,
		UplinkChunkSize:      (*option.Range[int])(s.UplinkChunkSize),
		SessionIDTable:       s.SessionIDTable,
		SeqPlacement:         s.SeqPlacement,
		SeqKey:               s.SeqKey,
		NoGRPCHeader:         s.NoGRPCHeader.Value(),
		NoSSEHeader:          s.NoSSEHeader.Value(),
		ScMaxEachPostBytes:   (*option.Range[int])(s.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: (*option.Range[int])(s.ScMinPostsIntervalMs),
		ScStreamUpServerSecs: (*option.Range[int])(s.ScStreamUpServerSecs),
		CongestionController: s.CongestionController,
		TrustedXForwardedFor: badoption.Listable[string](s.TrustedXForwardedFor),
	}
	var err error
	if base.SessionPlacement, err = firstOf("session placement", s.SessionIDPlacement, s.SessionPlacement); err != nil {
		return base, err
	}
	if base.SessionKey, err = firstOf("session key", s.SessionIDKey, s.SessionKey); err != nil {
		return base, err
	}
	maxHeaderBytes, err := firstInt("maximum header bytes", s.ServerMaxHeaderBytes, s.MaxHeaderBytes)
	if err != nil {
		return base, err
	}
	if base.ServerMaxHeaderBytes, err = maxHeaderBytes.Value("XHTTP maximum header bytes"); err != nil {
		return base, err
	}
	bufferedPosts, err := firstInt("buffered post limit", s.ScMaxBufferedPosts, s.ScMaxConcurrentPosts)
	if err != nil {
		return base, err
	}
	base.ScMaxBufferedPosts = int64(bufferedPosts)
	if base.CWND, err = s.CWND.Value("XHTTP cwnd"); err != nil {
		return base, err
	}
	if s.XPaddingBytes != nil {
		base.XPaddingBytes = option.Range[int](*s.XPaddingBytes)
	}
	if s.SessionIDLength != nil {
		base.SessionIDLength = option.Range[int](*s.SessionIDLength)
	}
	if s.Xmux != nil {
		base.Xmux = &option.V2RayXHTTPXmuxOptions{HKeepAlivePeriod: int64(s.Xmux.HKeepAlivePeriod)}
		for _, field := range []struct {
			source *subscription.Range
			target *option.Range[int]
		}{
			{s.Xmux.MaxConcurrency, &base.Xmux.MaxConcurrency},
			{s.Xmux.MaxConnections, &base.Xmux.MaxConnections},
			{s.Xmux.CMaxReuseTimes, &base.Xmux.CMaxReuseTimes},
			{s.Xmux.HMaxRequestTimes, &base.Xmux.HMaxRequestTimes},
			{s.Xmux.HMaxReusableSecs, &base.Xmux.HMaxReusableSecs},
		} {
			if field.source != nil {
				*field.target = option.Range[int](*field.source)
			}
		}
	}
	return base, nil
}

// Normalize fills in what a server assumes for the settings that are left out:
// Xray's padding range, then whatever sing-box's own decoder defaults.
func Normalize(options option.V2RayXHTTPOptions) (option.V2RayXHTTPOptions, error) {
	if options.XPaddingBytes.To == 0 {
		options.XPaddingBytes = DefaultPaddingBytes
	}
	if options.Download != nil && options.Download.XPaddingBytes.To == 0 {
		download := *options.Download
		download.XPaddingBytes = DefaultPaddingBytes
		options.Download = &download
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return options, err
	}
	var normalized option.V2RayXHTTPOptions
	if err = json.Unmarshal(encoded, &normalized); err != nil {
		return options, E.Cause(err, "invalid XHTTP settings")
	}
	return normalized, nil
}

func hasContent(content json.RawMessage) bool {
	if len(content) == 0 {
		return false
	}
	var value any
	if json.Unmarshal(content, &value) != nil {
		return true
	}
	switch typed := value.(type) {
	case nil:
		return false
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

// firstOf takes the value of two spellings of one setting, refusing a document
// that gives them different values rather than guessing which one the server
// was configured with.
func firstOf(name string, values ...string) (string, error) {
	var selected string
	for _, value := range values {
		if value == "" {
			continue
		}
		if selected != "" && value != selected {
			return "", E.New("conflicting XHTTP ", name)
		}
		selected = value
	}
	return selected, nil
}

func firstInt(name string, values ...subscription.Int) (subscription.Int, error) {
	var selected subscription.Int
	for _, value := range values {
		if value == 0 {
			continue
		}
		if selected != 0 && value != selected {
			return 0, E.New("conflicting XHTTP ", name)
		}
		selected = value
	}
	return selected, nil
}
