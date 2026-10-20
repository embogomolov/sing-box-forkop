// Package xhttp reads the XHTTP transport settings a subscription carries, in Xray's
// streamSettings, a share link's "extra" object and Clash's xhttp-opts. The client settings must
// match the server exactly, or the server answers a different request than the client makes.
package xhttp

import (
	"encoding/json"
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

	XPaddingBytes     *option.Range[int] `json:"xPaddingBytes"`
	XPaddingObfsMode  subscription.Bool  `json:"xPaddingObfsMode"`
	XPaddingKey       string             `json:"xPaddingKey"`
	XPaddingHeader    string             `json:"xPaddingHeader"`
	XPaddingPlacement string             `json:"xPaddingPlacement"`
	XPaddingMethod    string             `json:"xPaddingMethod"`

	UplinkHTTPMethod    string             `json:"uplinkHTTPMethod"`
	UplinkDataPlacement string             `json:"uplinkDataPlacement"`
	UplinkDataKey       string             `json:"uplinkDataKey"`
	UplinkChunkSize     *option.Range[int] `json:"uplinkChunkSize"`

	SessionIDPlacement string             `json:"sessionIDPlacement"`
	SessionPlacement   string             `json:"sessionPlacement"`
	SessionIDKey       string             `json:"sessionIDKey"`
	SessionKey         string             `json:"sessionKey"`
	SessionIDTable     string             `json:"sessionIDTable"`
	SessionIDLength    *option.Range[int] `json:"sessionIDLength"`

	SeqPlacement string `json:"seqPlacement"`
	SeqKey       string `json:"seqKey"`

	NoGRPCHeader subscription.Bool `json:"noGRPCHeader"`
	NoSSEHeader  subscription.Bool `json:"noSSEHeader"`

	ScMaxEachPostBytes   *option.Range[int] `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs *option.Range[int] `json:"scMinPostsIntervalMs"`
	ScStreamUpServerSecs *option.Range[int] `json:"scStreamUpServerSecs"`
	ScMaxBufferedPosts   subscription.Int   `json:"scMaxBufferedPosts"`
	ScMaxConcurrentPosts subscription.Int   `json:"scMaxConcurrentPosts"`

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
	MaxConcurrency   *option.Range[int] `json:"maxConcurrency"`
	MaxConnections   *option.Range[int] `json:"maxConnections"`
	CMaxReuseTimes   *option.Range[int] `json:"cMaxReuseTimes"`
	HMaxRequestTimes *option.Range[int] `json:"hMaxRequestTimes"`
	HMaxReusableSecs *option.Range[int] `json:"hMaxReusableSecs"`
	HKeepAlivePeriod subscription.Int   `json:"hKeepAlivePeriod"`
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

// Build renders the settings through sing-box's own decoder, which fills in a server's defaults
// and refuses a combination sing-box cannot dial, so a broken XHTTP node is reported here.
func (s Settings) Build() (*option.V2RayTransportOptions, error) {
	if hasContent(s.DownloadSettings) {
		return nil, E.New("XHTTP download settings cannot be represented")
	}
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
		UplinkChunkSize:      s.UplinkChunkSize,
		SessionIDTable:       s.SessionIDTable,
		SeqPlacement:         s.SeqPlacement,
		SeqKey:               s.SeqKey,
		NoGRPCHeader:         s.NoGRPCHeader.Value(),
		NoSSEHeader:          s.NoSSEHeader.Value(),
		ScMaxEachPostBytes:   s.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: s.ScMinPostsIntervalMs,
		ScStreamUpServerSecs: s.ScStreamUpServerSecs,
		CongestionController: s.CongestionController,
		TrustedXForwardedFor: badoption.Listable[string](s.TrustedXForwardedFor),
	}
	var err error
	if base.SessionPlacement, err = firstOf("session placement", s.SessionIDPlacement, s.SessionPlacement); err != nil {
		return nil, err
	}
	if base.SessionKey, err = firstOf("session key", s.SessionIDKey, s.SessionKey); err != nil {
		return nil, err
	}
	maxHeaderBytes, err := firstInt("maximum header bytes", s.ServerMaxHeaderBytes, s.MaxHeaderBytes)
	if err != nil {
		return nil, err
	}
	if base.ServerMaxHeaderBytes, err = maxHeaderBytes.Value("XHTTP maximum header bytes"); err != nil {
		return nil, err
	}
	bufferedPosts, err := firstInt("buffered post limit", s.ScMaxBufferedPosts, s.ScMaxConcurrentPosts)
	if err != nil {
		return nil, err
	}
	base.ScMaxBufferedPosts = int64(bufferedPosts)
	if base.CWND, err = s.CWND.Value("XHTTP cwnd"); err != nil {
		return nil, err
	}
	if s.XPaddingBytes != nil {
		base.XPaddingBytes = *s.XPaddingBytes
	}
	if s.SessionIDLength != nil {
		base.SessionIDLength = *s.SessionIDLength
	}
	if s.Xmux != nil {
		base.Xmux = &option.V2RayXHTTPXmuxOptions{HKeepAlivePeriod: int64(s.Xmux.HKeepAlivePeriod)}
		for _, field := range []struct {
			source *option.Range[int]
			target *option.Range[int]
		}{
			{s.Xmux.MaxConcurrency, &base.Xmux.MaxConcurrency},
			{s.Xmux.MaxConnections, &base.Xmux.MaxConnections},
			{s.Xmux.CMaxReuseTimes, &base.Xmux.CMaxReuseTimes},
			{s.Xmux.HMaxRequestTimes, &base.Xmux.HMaxRequestTimes},
			{s.Xmux.HMaxReusableSecs, &base.Xmux.HMaxReusableSecs},
		} {
			if field.source != nil {
				*field.target = *field.source
			}
		}
	}
	normalized, err := Normalize(option.V2RayXHTTPOptions{Mode: s.Mode, V2RayXHTTPBaseOptions: base})
	if err != nil {
		return nil, err
	}
	return &option.V2RayTransportOptions{
		Type:         C.V2RayTransportTypeXHTTP,
		XHTTPOptions: normalized,
	}, nil
}

// Normalize fills in what a server assumes for the settings that are left out:
// Xray's padding range, then whatever sing-box's own decoder defaults.
func Normalize(options option.V2RayXHTTPOptions) (option.V2RayXHTTPOptions, error) {
	if options.XPaddingBytes.To == 0 {
		options.XPaddingBytes = DefaultPaddingBytes
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
