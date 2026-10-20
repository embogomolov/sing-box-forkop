package group

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

type testSelectorOutbound struct {
	outboundAdapter.Adapter
	dialCount atomic.Int32
}

type blockingURLTestOutbound struct {
	outboundAdapter.Adapter
	started chan struct{}
	once    sync.Once
}

func (t *blockingURLTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	t.once.Do(func() { close(t.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *blockingURLTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (t *testSelectorOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	t.dialCount.Add(1)
	return nil, errors.New("test outbound dialed")
}

func (t *testSelectorOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

type testOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type testProvider struct {
	adapter.Provider
	tag       string
	outbounds []adapter.Outbound
	callbacks list.List[adapter.ProviderUpdateCallback]
}

func (p *testProvider) Tag() string { return p.tag }

func (p *testProvider) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), p.outbounds...)
}

func (p *testProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return p.callbacks.PushBack(callback)
}

func (p *testProvider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}

func (p *testProvider) callbackCount() int {
	count := 0
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		count++
	}
	return count
}

type testProviderManager struct {
	adapter.ProviderManager
	providers map[string]adapter.Provider
}

func (m *testProviderManager) Providers() []adapter.Provider {
	providers := make([]adapter.Provider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, provider)
	}
	return providers
}

func (m *testProviderManager) Get(tag string) (adapter.Provider, bool) {
	provider, loaded := m.providers[tag]
	return provider, loaded
}

func newTestOutbound(tag string) *testSelectorOutbound {
	return &testSelectorOutbound{Adapter: outboundAdapter.NewAdapter("test", tag, []string{"tcp", "udp"}, nil)}
}

func newTypedTestOutbound(outboundType string, tag string) *testSelectorOutbound {
	return &testSelectorOutbound{Adapter: outboundAdapter.NewAdapter(outboundType, tag, []string{"tcp", "udp"}, nil)}
}

func TestGroupsExcludeProviderOutboundTypes(t *testing.T) {
	keep := newTypedTestOutbound(C.TypeVLESS, "provider/keep")
	drop := newTypedTestOutbound(C.TypeShadowsocks, "provider/drop")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		keep.Tag(): keep,
		drop.Tag(): drop,
	}}
	provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{keep, drop}}
	providers := map[string]adapter.Provider{provider.Tag(): provider}
	excludeTypes := excludedOutboundTypes([]string{" Shadowsocks "})
	nopLogger := log.NewNOPFactory().NewLogger("test")

	selector := &Selector{
		outboundsCache: make(map[string][]adapter.Outbound),
		Adapter:        outboundAdapter.NewAdapter(C.TypeSelector, "selector", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		outbounds:      make(map[string]adapter.Outbound),
		interruptGroup: interrupt.NewGroup(),
		providers:      providers,
		providerTags:   []string{provider.Tag()},
		excludeTypes:   excludeTypes,
	}
	if err := selector.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := selector.All(); len(all) != 1 || all[0] != keep.Tag() {
		t.Fatalf("selector kept an excluded outbound type: %v", all)
	}

	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, nopLogger, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         nopLogger,
		group:          urlTestGroup,
		providers:      providers,
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
		excludeTypes:   excludeTypes,
	}
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := urlTest.All(); len(all) != 1 || all[0] != keep.Tag() {
		t.Fatalf("urltest kept an excluded outbound type: %v", all)
	}

	fallback := &Fallback{
		Adapter:   outboundAdapter.NewAdapter(C.TypeFallback, "fallback", []string{"tcp", "udp"}, nil),
		ctx:       context.Background(),
		outbound:  manager,
		logger:    nopLogger,
		providers: providers,
		groups: []fallbackGroup{{
			providerTags: []string{provider.Tag()},
			excludeTypes: excludeTypes,
		}},
	}
	if err := fallback.rebuildCandidates(); err != nil {
		t.Fatal(err)
	}
	if all := fallback.All(); len(all) != 1 || all[0] != keep.Tag() {
		t.Fatalf("fallback kept an excluded outbound type: %v", all)
	}
}

func TestProviderOutboundFilterTag(t *testing.T) {
	if actual := providerOutboundFilterTag("subscription", "subscription/Node #2"); actual != "Node #2" {
		t.Fatalf("unexpected provider-local filter tag: %q", actual)
	}
}

func TestSelectorUnregistersProviderCallbacks(t *testing.T) {
	provider := &testProvider{tag: "provider"}
	manager := &testProviderManager{providers: map[string]adapter.Provider{provider.Tag(): provider}}
	selector := &Selector{
		outboundsCache: make(map[string][]adapter.Outbound),
		Adapter:        outboundAdapter.NewAdapter(C.TypeSelector, "selector", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		provider:       manager,
		providers:      make(map[string]adapter.Provider),
		providerTags:   []string{provider.Tag()},
		outbounds:      make(map[string]adapter.Outbound),
		interruptGroup: interrupt.NewGroup(),
	}
	if err := selector.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))); err != nil {
		t.Fatal(err)
	}
	if count := provider.callbackCount(); count != 1 {
		t.Fatalf("unexpected callback count after start: %d", count)
	}
	if err := selector.Close(); err != nil {
		t.Fatal(err)
	}
	if count := provider.callbackCount(); count != 0 {
		t.Fatalf("provider callback leaked after close: %d", count)
	}

	selector.providerTags = []string{provider.Tag(), "missing"}
	if err := selector.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))); err == nil {
		t.Fatal("missing provider was accepted")
	}
	if count := provider.callbackCount(); count != 0 {
		t.Fatalf("provider callback leaked after failed start: %d", count)
	}
}

func TestProviderGroupsFailClosedAndRecover(t *testing.T) {
	compatible := newTestOutbound("Compatible")
	node := newTestOutbound("provider/node")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		compatible.Tag(): compatible,
		node.Tag():       node,
	}}
	provider := &testProvider{tag: "provider"}

	selector := &Selector{
		outboundsCache: make(map[string][]adapter.Outbound),
		Adapter:        outboundAdapter.NewAdapter(C.TypeSelector, "selector", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		outbounds:      make(map[string]adapter.Outbound),
		interruptGroup: interrupt.NewGroup(),
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		providerTags:   []string{provider.Tag()},
	}
	if err := selector.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(selector.All()) != 0 || selector.Now() != "" {
		t.Fatalf("empty selector unexpectedly selected %q from %v", selector.Now(), selector.All())
	}
	if _, err := selector.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("empty selector dial succeeded")
	}

	nopLogger := log.NewNOPFactory().NewLogger("test")
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, nopLogger, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         nopLogger,
		group:          urlTestGroup,
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
	}
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(urlTest.All()) != 0 {
		t.Fatalf("empty urltest unexpectedly contains %v", urlTest.All())
	}
	if _, err := urlTest.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("empty urltest dial succeeded")
	}
	if compatible.dialCount.Load() != 0 {
		t.Fatalf("empty provider groups dialed Compatible %d times", compatible.dialCount.Load())
	}

	provider.outbounds = []adapter.Outbound{node}
	if err := selector.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if selector.Now() != node.Tag() || len(selector.All()) != 1 {
		t.Fatalf("selector did not recover after provider refresh: now=%q all=%v", selector.Now(), selector.All())
	}
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := urlTest.All(); len(all) != 1 || all[0] != node.Tag() {
		t.Fatalf("urltest did not recover after provider refresh: %v", all)
	}
}

func TestURLTestProviderRefreshDoesNotWaitForHealthChecks(t *testing.T) {
	nodeA := &blockingURLTestOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "provider/node-a", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	nodeB := &blockingURLTestOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "provider/node-b", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		nodeA.Tag(): nodeA,
		nodeB.Tag(): nodeB,
	}}
	provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{nodeA}}
	nopLogger := log.NewNOPFactory().NewLogger("test")
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, nopLogger, nil, "http://example.com", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTestGroup.history.StoreURLTestHistory(nodeA.Tag(), &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: 1,
	})
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         nopLogger,
		group:          urlTestGroup,
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
	}

	done := make(chan error, 1)
	go func() { done <- urlTest.onProviderUpdated(provider.Tag()) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("provider refresh waited for URL tests")
	}
	select {
	case <-nodeA.started:
	case <-time.After(time.Second):
		t.Fatal("provider refresh did not start URL tests")
	}

	provider.outbounds = []adapter.Outbound{nodeB}
	if err = urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-nodeB.started:
	case <-time.After(time.Second):
		t.Fatal("new provider refresh was lost while a previous URL test was running")
	}
	urlTest.cancel()
}

func TestURLTestInterruptsAfterProviderSelectionChanges(t *testing.T) {
	oldNode := newTestOutbound("provider/old")
	newNode := newTestOutbound("provider/new")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{newNode.Tag(): newNode}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{newNode}, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	group.selectedOutboundTCP = oldNode
	group.storeHistory(newNode.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	conn, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	group.interruptGroup.NewConn(conn, false)
	if err = peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	group.performUpdateCheck()
	if group.selectedOutboundTCP == nil || group.selectedOutboundTCP.Tag() != newNode.Tag() {
		t.Fatalf("new provider outbound was not selected: %#v", group.selectedOutboundTCP)
	}
	if _, err = peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("connection survived a provider selection change: %v", err)
	}
}
