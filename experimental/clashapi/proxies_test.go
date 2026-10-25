package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type linkAPIOutbound struct {
	adapter.Outbound
	outboundAdapter.Adapter
}

func (o *linkAPIOutbound) Type() string           { return o.Adapter.Type() }
func (o *linkAPIOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *linkAPIOutbound) Network() []string      { return o.Adapter.Network() }
func (o *linkAPIOutbound) Dependencies() []string { return o.Adapter.Dependencies() }

type linkAPIOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *linkAPIOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }
func (m *linkAPIOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, outbound := range m.outbounds {
		if outbound.Tag() == tag {
			return outbound, true
		}
	}
	return nil, false
}
func (m *linkAPIOutboundManager) Default() adapter.Outbound { return m.outbounds[0] }

type linkAPIProvider struct {
	adapter.Provider
	links  map[string]string
	errors map[string]error
}

func (p *linkAPIProvider) OutboundLink(tag string) (string, bool, error) {
	link, loaded := p.links[tag]
	return link, loaded, p.errors[tag]
}

type linkAPIProviderManager struct {
	adapter.ProviderManager
	providers []adapter.Provider
}

func (m *linkAPIProviderManager) Providers() []adapter.Provider { return m.providers }

type linkAPIEndpointManager struct{ adapter.EndpointManager }

func (m *linkAPIEndpointManager) Endpoints() []adapter.Endpoint { return nil }

type unifiedDelayProbeOutbound struct {
	*linkAPIOutbound
	unifiedDelay bool
}

func (o *unifiedDelayProbeOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.unifiedDelay = urltest.IsUnifiedDelayFromContext(ctx)
	return nil, errors.New("probe")
}

func (o *unifiedDelayProbeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("probe")
}

func TestProxyLinkAPIUsesCommonAuthenticationAndIsUncached(t *testing.T) {
	const (
		tag       = "subscription/node"
		secretURI = "vless://00000000-0000-4000-8000-000000000001@example.com:443#node"
	)
	outbound := &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil)}
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}},
		endpoint:       &linkAPIEndpointManager{},
		provider:       &linkAPIProviderManager{providers: []adapter.Provider{&linkAPIProvider{links: map[string]string{tag: secretURI}}}},
		urlTestHistory: urltest.NewHistoryStorage(),
	}
	handler := authentication("api-secret")(proxyRouter(server, nil))

	request := httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated link request returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated link request returned %d: %s", response.Code, response.Body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected Cache-Control: %q", response.Header().Get("Cache-Control"))
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.URL != secretURI {
		t.Fatalf("unexpected link response: %q", result.URL)
	}
	openHandler := authentication("")(proxyRouter(server, nil))
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response = httptest.NewRecorder()
	openHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("remote link request without an API secret returned %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response = httptest.NewRecorder()
	openHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local link request without an API secret returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("bulk proxy request returned %d: %s", response.Code, response.Body)
	}
	if strings.Contains(response.Body.String(), secretURI) || strings.Contains(response.Body.String(), `"url"`) {
		t.Fatalf("bulk proxy response leaked a share link: %s", response.Body)
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fmissing/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing proxy returned %d", response.Code)
	}

	server.provider = &linkAPIProviderManager{providers: []adapter.Provider{&linkAPIProvider{
		links:  map[string]string{tag: ""},
		errors: map[string]error{tag: errors.New("unsupported options")},
	}}}
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsupported proxy returned %d with Cache-Control %q", response.Code, response.Header().Get("Cache-Control"))
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("remote link request returned %d with Cache-Control %q", response.Code, response.Header().Get("Cache-Control"))
	}
}

func TestProxyDelayPreservesUnifiedDelayContext(t *testing.T) {
	const tag = "subscription/node"
	outbound := &unifiedDelayProbeOutbound{
		linkAPIOutbound: &linkAPIOutbound{
			Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil),
		},
	}
	ctx := urltest.ContextWithIsUnifiedDelay(context.Background())
	clashServer, err := NewServer(clashTestContext(ctx), log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}}

	request := httptest.NewRequest(http.MethodGet, "/proxies/subscription%2Fnode/delay?url=https%3A%2F%2Fexample.com&timeout=100", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	if !outbound.unifiedDelay {
		t.Fatal("proxy delay request lost Unified Delay context")
	}
}

// A Forkop tag holds a slash and may hold a number sign, so a group is addressed by an encoded
// path; an unencoded tag names another, nonexistent proxy.
func TestFallbackGroupSelectionThroughProxiesAPI(t *testing.T) {
	const (
		groupTag        = "proxy/Fallback #1"
		encodedGroupTag = "proxy%2FFallback%20%231"
		firstTag        = "proxy/Node A"
		secondTag       = "proxy/Node B"
	)
	first := &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, firstTag, []string{"tcp", "udp"}, nil)}
	second := &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, secondTag, []string{"tcp", "udp"}, nil)}
	manager := &linkAPIOutboundManager{outbounds: []adapter.Outbound{first, second}}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	fallback, err := group.NewFallback(
		ctx,
		nil,
		log.NewNOPFactory().NewLogger("test"),
		groupTag,
		option.FallbackOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{Outbounds: []string{firstTag, secondTag}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = fallback.(adapter.Lifecycle).Start(adapter.StartStateStart, adapter.NewScope(ctx, log.NewNOPFactory().NewLogger("test"))); err != nil {
		t.Fatal(err)
	}
	manager.outbounds = []adapter.Outbound{fallback, first, second}

	clashServer, err := NewServer(clashTestContext(ctx), log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = manager
	server.endpoint = &linkAPIEndpointManager{}

	selectProxy := func(name string) int {
		request := httptest.NewRequest(http.MethodPut, "/proxies/"+encodedGroupTag, strings.NewReader(`{"name":"`+name+`"}`))
		request.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response.Code
	}
	groupInfo := func() map[string]any {
		request := httptest.NewRequest(http.MethodGet, "/proxies/"+encodedGroupTag, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		var info map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		return info
	}

	if code := selectProxy(secondTag); code != http.StatusNoContent {
		t.Fatalf("selecting a Fallback member returned %d", code)
	}
	if info := groupInfo(); info["now"] != secondTag || info["fixed"] != secondTag {
		t.Fatalf("the pin was not applied: now=%v fixed=%v", info["now"], info["fixed"])
	}
	if code := selectProxy("proxy/Missing"); code != http.StatusBadRequest {
		t.Fatalf("selecting an unknown member returned %d", code)
	}
	if code := selectProxy(""); code != http.StatusNoContent {
		t.Fatalf("releasing the pin returned %d", code)
	}
	if info := groupInfo(); info["now"] != firstTag || info["fixed"] != "" {
		t.Fatalf("the pin was not released: now=%v fixed=%v", info["now"], info["fixed"])
	}

	request := httptest.NewRequest(http.MethodPut, "/proxies/proxy/Fallback%20%231", strings.NewReader(`{"name":"`+secondTag+`"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code == http.StatusNoContent {
		t.Fatal("a group tag whose slash is left unencoded must not resolve to the group")
	}
}

// A single-node delay test takes any timeout; a sixteen-bit parse refused everything over 32767 ms.
func TestProxyDelayAcceptsATimeoutOverSixteenBits(t *testing.T) {
	const tag = "subscription/node"
	outbound := &unifiedDelayProbeOutbound{
		linkAPIOutbound: &linkAPIOutbound{
			Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil),
		},
	}
	clashServer, err := NewServer(clashTestContext(context.Background()), log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}}

	request := httptest.NewRequest(
		http.MethodGet,
		"/proxies/subscription%2Fnode/delay?url=https%3A%2F%2Fexample.com&timeout=40000",
		nil,
	)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	// The probe outbound refuses to dial, so the test itself fails - what must
	// not happen is the request being rejected before the test is even run.
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("delay request with a 40 s timeout returned %d: %s", response.Code, response.Body)
	}
}

func clashTestContext(ctx context.Context) context.Context {
	ctx = service.ContextWithPtr(ctx, trafficcontrol.NewManager())
	ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	return service.ContextWithPtr(ctx, clashmode.NewManager(ctx, log.NewNOPFactory().NewLogger("test"), "Rule", nil))
}
