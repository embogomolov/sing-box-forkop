package provider

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

func TestFilterOutboundsUsesRuntimeTags(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{Prefix: "US "})
	normalized, err := provider.FilterOutbounds([]option.Outbound{
		{Tag: "Node"},
		{Tag: "Node"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, outbound := range normalized {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"US Node", "US Node #2"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected filter tags: %v", tags)
	}
}

func TestFlagToCountryCodeAllFlags(t *testing.T) {
	for first := 'A'; first <= 'Z'; first++ {
		for second := 'A'; second <= 'Z'; second++ {
			flag := string(rune(0x1F1E6+(first-'A'))) + string(rune(0x1F1E6+(second-'A')))
			expected := string(first) + string(second)
			result := flagToCountryCode(flag)
			// flagToCountryCode appends a space
			if result != expected+" " {
				t.Errorf("flagToCountryCode(%q) = %q, want %q", expected, result, expected+" ")
			}
		}
	}
}

func TestRemoveEmojisFromTag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"🇺🇸 United States", "US United States"},
		{"🇷🇺 Россия", "RU Россия"},
		{"🇩🇪 Germany 🚀", "DE Germany"},
		{"🇫🇷🇬🇧 France-UK", "FR GB France-UK"},
		{"No emojis here", "No emojis here"},
		{"🌍 World", "World"},
		{"🇯🇵 Tokyo ⚡ Fast", "JP Tokyo Fast"},
		{"Germany 🇩🇪", "Germany DE"},
		{"Server 🇺🇸 Node", "Server US Node"},
	}
	for _, tt := range tests {
		if tag := removeEmojisFromTag(tt.input); tag != tt.expected {
			t.Errorf("removeEmojisFromTag(%q) = %q, want %q", tt.input, tag, tt.expected)
		}
	}
}

func TestRemoveEmojisRenamesTheDetourOfAChain(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeHTTP, Tag: "🇩🇪 Base", Options: &option.HTTPOutboundOptions{}},
		{Type: C.TypeHTTP, Tag: "Chain", Options: &option.HTTPOutboundOptions{DialerOptions: option.DialerOptions{Detour: "🇩🇪 Base"}}},
	}
	normalizeOutboundTags(outbounds, true, nil)
	if outbounds[0].Tag != "DE Base" || outbounds[1].Options.(*option.HTTPOutboundOptions).Detour != "DE Base" {
		t.Fatalf("emoji removal broke the chain: %q <- %q", outbounds[0].Tag, outbounds[1].Options.(*option.HTTPOutboundOptions).Detour)
	}
}

func TestNativeDialerOverridePreservesSourcesAndComposesWithPatch(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{Patch: map[string]any{"tcp_fast_open": true}})
	provider.ctx = newOverrideContext(t)
	baseline := &option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "wan"}}
	provider.SetOverrideDialerOptions(baseline)
	source := &option.HTTPOutboundOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "old", TCPMultiPath: true}}}
	filtered, err := provider.FilterOutbounds([]option.Outbound{{Type: C.TypeHTTP, Tag: "Node", Options: source}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual := filtered[0].Options.(*option.HTTPOutboundOptions).DialerOptions
	if actual.BindInterface != "wan" || actual.TCPMultiPath || !actual.TCPFastOpen {
		t.Fatalf("native replacement and explicit override were not composed: %+v", actual)
	}
	if source.BindInterface != "old" || !source.TCPMultiPath || source.TCPFastOpen || baseline.TCPFastOpen {
		t.Fatal("dialer override mutated source or reusable baseline")
	}
}

func TestFilterOutbounds(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{Prefix: "US "})
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{Tag: "Keep"},
		{Tag: "Skip"},
		{Tag: "Keep"},
	}, regexp.MustCompile(`Skip`), regexp.MustCompile(`^US `))
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, outbound := range filtered {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"US Keep", "US Keep #2"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected filtered tags: %v", tags)
	}
}

func TestFilterOutboundsKeepsTheTagsTheNameFiltersChoseFrom(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{Prefix: "US "})
	provider.SetExcludeTypes([]string{C.TypeTrojan})
	_, err := provider.FilterOutbounds([]option.Outbound{
		{Tag: "Keep"},
		{Tag: "Skip"},
		{Type: C.TypeTrojan, Tag: "Excluded type"},
		{Tag: "Keep"},
	}, regexp.MustCompile(`Skip`), regexp.MustCompile(`Nothing`))
	if err != nil {
		t.Fatal(err)
	}
	if expected := []string{"US Keep", "US Skip", "US Keep #2"}; !reflect.DeepEqual(provider.FilterCandidates(), expected) {
		t.Fatalf("unexpected filter candidates: %v", provider.FilterCandidates())
	}
}

func TestFilterOutboundsExcludesTypes(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{})
	provider.SetExcludeTypes([]string{" Shadowsocks ", "", "TROJAN"})
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{Type: C.TypeVLESS, Tag: "Keep"},
		{Type: C.TypeShadowsocks, Tag: "Base"},
		{Type: C.TypeTrojan, Tag: "Drop"},
		{
			Type:    C.TypeVLESS,
			Tag:     "Chained",
			Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "Base"}},
		},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, outbound := range filtered {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"Keep"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected filtered tags: %v", tags)
	}
}

func mustRegexp(t *testing.T, pattern string) *badoption.Regexp {
	t.Helper()
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return (*badoption.Regexp)(compiled)
}

func newTagOverrideProvider(t *testing.T, options option.ProviderOverrideOptions) *Adapter {
	t.Helper()
	logFactory := log.NewNOPFactory()
	provider := &Adapter{logFactory: logFactory, logger: logFactory.NewLogger("test")}
	if err := provider.SetOverride(options); err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestOverrideRewritesTags(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{
		Prefix: "[sub] ",
		Suffix: " (fast)",
		Rename: []option.ProviderRenameOptions{
			{Pattern: mustRegexp(t, `^HK-(.*)$`), Target: "Hong Kong $1"},
			{Pattern: mustRegexp(t, `\s+`), Target: " "},
		},
	})
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{Tag: "HK-01"},
		{Tag: "HK-01"},
		{Tag: ""},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, outbound := range filtered {
		tags = append(tags, outbound.Tag)
	}
	expected := []string{"[sub] Hong Kong 01 (fast)", "[sub] Hong Kong 01 (fast) #2", "Node #3"}
	if !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected overridden tags: %v", tags)
	}
}

func newOverrideContext(t *testing.T) context.Context {
	t.Helper()
	registry := outboundAdapter.NewRegistry()
	outboundAdapter.Register[option.HTTPOutboundOptions](registry, C.TypeHTTP, nil)
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, C.TypeVLESS, nil)
	outboundAdapter.Register[option.ShadowsocksOutboundOptions](registry, C.TypeShadowsocks, nil)
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	return service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
}

func TestOverrideAppliesOptionsWhereTheTypeSupportsThem(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{
		Patch: map[string]any{
			"tcp_fast_open": true,
			"tls":           map[string]any{"insecure": true},
			"udp_over_tcp":  map[string]any{"enabled": true},
			"multiplex":     map[string]any{"enabled": true, "protocol": "h2mux"},
		},
	})
	provider.ctx = newOverrideContext(t)
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{
			Type:    C.TypeVLESS,
			Tag:     "vless",
			Options: &option.VLESSOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}}},
		},
		{Type: C.TypeShadowsocks, Tag: "ss", Options: &option.ShadowsocksOutboundOptions{Method: "none"}},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 2 {
		t.Fatalf("override dropped outbounds: %v", filtered)
	}

	vless := filtered[0].Options.(*option.VLESSOutboundOptions)
	if !vless.TCPFastOpen {
		t.Fatal("patch did not reach the VLESS dialer")
	}
	if vless.TLS == nil || !vless.TLS.Insecure {
		t.Fatal("patch did not reach the VLESS TLS options")
	}
	if vless.Multiplex == nil || !vless.Multiplex.Enabled || vless.Multiplex.Protocol != "h2mux" {
		t.Fatal("patch did not reach a field the VLESS outbound declares")
	}

	shadowsocks := filtered[1].Options.(*option.ShadowsocksOutboundOptions)
	if !shadowsocks.TCPFastOpen {
		t.Fatal("patch did not reach the Shadowsocks dialer")
	}
	if shadowsocks.UDPOverTCP == nil || !shadowsocks.UDPOverTCP.Enabled {
		t.Fatal("patch did not reach a field the Shadowsocks outbound declares")
	}
	if shadowsocks.Method != "none" {
		t.Fatal("patch lost an unrelated option of the Shadowsocks outbound")
	}
	if shadowsocks.Multiplex == nil || !shadowsocks.Multiplex.Enabled {
		t.Fatal("patch did not reach the shared multiplex field")
	}
}

func TestNormalizeOutboundsAssignsStableAnonymousTags(t *testing.T) {
	normalized := []option.Outbound{{}, {}}
	normalizeOutboundTags(normalized, false, nil)
	if normalized[0].Tag != "Node #1" || normalized[1].Tag != "Node #2" {
		t.Fatalf("unexpected anonymous tags: %q, %q", normalized[0].Tag, normalized[1].Tag)
	}
}

type linkTestOutbound struct {
	adapter.Outbound
	outboundAdapter.Adapter
}

func (o *linkTestOutbound) Type() string           { return o.Adapter.Type() }
func (o *linkTestOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *linkTestOutbound) Network() []string      { return o.Adapter.Network() }
func (o *linkTestOutbound) Dependencies() []string { return o.Adapter.Dependencies() }

type linkTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *linkTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type filteringTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

type closingTestOutboundManager struct {
	adapter.OutboundManager
	removed []string
}

func (m *closingTestOutboundManager) Remove(tag string) error {
	m.removed = append(m.removed, tag)
	return nil
}

func TestProviderClosesDependentsBeforeDependencies(t *testing.T) {
	manager := new(closingTestOutboundManager)
	provider := &Adapter{
		outbound:           manager,
		outboundCloseOrder: []string{"subscription/hop", "subscription/edge"},
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if expected := []string{"subscription/edge", "subscription/hop"}; !reflect.DeepEqual(manager.removed, expected) {
		t.Fatalf("unexpected close order: %v", manager.removed)
	}
}

func (m *filteringTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func (m *filteringTestOutboundManager) WithStage(fn func(stage adapter.StartStage, scope *adapter.Scope)) {
	fn(adapter.StartStateStarted, adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test")))
}

func (m *filteringTestOutboundManager) SwapBatch(expectedOld map[string]adapter.Outbound, candidates []adapter.Outbound) (map[string]adapter.Outbound, error) {
	old := make(map[string]adapter.Outbound, len(expectedOld))
	for tag, expected := range expectedOld {
		if m.outbounds[tag] != expected {
			return nil, errors.New("unexpected old outbound")
		}
		old[tag] = expected
		delete(m.outbounds, tag)
	}
	for _, candidate := range candidates {
		m.outbounds[candidate.Tag()] = candidate
	}
	return old, nil
}

func TestProviderSkipsInvalidOutboundsAndKeepsAtomicFallback(t *testing.T) {
	registry := outboundAdapter.NewRegistry()
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, "valid", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.VLESSOutboundOptions) (adapter.Outbound, error) {
		return &linkTestOutbound{Adapter: outboundAdapter.NewAdapter("valid", tag, nil, nil)}, nil
	})
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, "invalid", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, _ string, _ option.VLESSOutboundOptions) (adapter.Outbound, error) {
		return nil, errors.New("invalid test outbound")
	})
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	manager := &filteringTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	logFactory := log.NewNOPFactory()
	provider := &Adapter{
		ctx:         ctx,
		outbound:    manager,
		logFactory:  logFactory,
		logger:      logFactory.NewLogger("test"),
		providerTag: "subscription",
	}
	err := provider.UpdateOutbounds([]option.Outbound{
		{Type: "valid", Tag: "working", Options: &option.VLESSOutboundOptions{}},
		{Type: "invalid", Tag: "broken", Options: &option.VLESSOutboundOptions{}},
		{Type: "valid", Tag: "dependent", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "broken"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.Outbounds()) != 1 || provider.Outbounds()[0].Tag() != "subscription/working" {
		t.Fatalf("invalid provider nodes were not isolated: %v", provider.Outbounds())
	}
	working := provider.Outbounds()[0]
	if err = provider.UpdateOutbounds([]option.Outbound{
		{Type: "invalid", Tag: "broken", Options: &option.VLESSOutboundOptions{}},
	}); err == nil {
		t.Fatal("provider with no usable outbounds must fail")
	}
	if current, loaded := manager.Outbound(working.Tag()); !loaded || current != working {
		t.Fatal("failed provider refresh replaced the last working state")
	}
	if err = provider.UpdateOutbounds(nil); err == nil {
		t.Fatal("provider update to an empty set must fail while it has outbounds")
	}
	if len(provider.Outbounds()) != 1 {
		t.Fatalf("empty provider update dropped the last working nodes: %v", provider.Outbounds())
	}
}

func TestProviderPublishesOnlyGeneratedOutboundLinks(t *testing.T) {
	runtimeOutbound := &linkTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "subscription/node", nil, nil)}
	provider := &Adapter{outbound: &linkTestOutboundManager{outbounds: map[string]adapter.Outbound{
		runtimeOutbound.Tag(): runtimeOutbound,
	}}}
	prepared := []preparedOutbound{
		{
			tag: "subscription/node",
			source: option.Outbound{
				Type: C.TypeVLESS,
				Tag:  "node",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
					UUID:          "00000000-0000-4000-8000-000000000001",
				},
			},
		},
	}
	if err := provider.publishOutbounds(prepared); err != nil {
		t.Fatal(err)
	}
	link, loaded, linkErr := provider.OutboundLink(runtimeOutbound.Tag())
	if !loaded || linkErr != nil || link != "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=none&type=tcp#node" {
		t.Fatalf("unexpected provider outbound link: loaded=%v link=%q error=%v", loaded, link, linkErr)
	}
	if _, loaded, _ = provider.OutboundLink("subscription/missing"); loaded {
		t.Fatal("unexpected link for missing provider outbound")
	}

	unsupported := &linkTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeSSH, "subscription/ssh", nil, nil)}
	provider.outbound.(*linkTestOutboundManager).outbounds[unsupported.Tag()] = unsupported
	if err := provider.publishOutbounds([]preparedOutbound{{
		tag: unsupported.Tag(), source: option.Outbound{Type: C.TypeSSH, Tag: "ssh", Options: &option.SSHOutboundOptions{}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, loaded, linkErr = provider.OutboundLink(unsupported.Tag()); !loaded || linkErr == nil {
		t.Fatal("unsupported outbound did not expose its link-generation error")
	}
	if _, loaded, _ = provider.OutboundLink(runtimeOutbound.Tag()); loaded {
		t.Fatal("removed outbound link survived provider refresh")
	}
}

func TestFilterOutboundsDropsChainsExcludedByName(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{})
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{Type: C.TypeVLESS, Tag: "Base", Options: &option.VLESSOutboundOptions{}},
		{
			Type:    C.TypeVLESS,
			Tag:     "Chained",
			Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "Base"}},
		},
		{Type: C.TypeVLESS, Tag: "Plain", Options: &option.VLESSOutboundOptions{}},
	}, regexp.MustCompile(`^Base$`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, outbound := range filtered {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"Plain"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected filtered tags: %v", tags)
	}
}

func TestNormalizeOutboundTagsNumbersUntilTheNameIsFree(t *testing.T) {
	normalized := []option.Outbound{{Tag: "A"}, {Tag: "A"}, {Tag: "A #2"}}
	normalizeOutboundTags(normalized, false, nil)
	var tags []string
	for _, outbound := range normalized {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"A", "A #2", "A #2 #2"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected deduplicated tags: %v", tags)
	}
}

func TestOverrideRejectsEmptyRenamePattern(t *testing.T) {
	_, err := newOverride(option.ProviderOverrideOptions{
		Rename: []option.ProviderRenameOptions{{Pattern: mustRegexp(t, ""), Target: "X"}},
	})
	if err == nil {
		t.Fatal("an empty rename pattern was accepted")
	}
}

type warningTestLogger struct {
	log.ContextLogger
	warnings int
}

func (l *warningTestLogger) Warn(args ...any) { l.warnings++ }

func TestFilterOutboundsReportsAFilterThatMatchesNothing(t *testing.T) {
	provider := newTagOverrideProvider(t, option.ProviderOverrideOptions{})
	logger := &warningTestLogger{ContextLogger: provider.logger}
	provider.logger = logger
	filtered, err := provider.FilterOutbounds([]option.Outbound{
		{Type: C.TypeVLESS, Tag: "Keep", Options: &option.VLESSOutboundOptions{}},
	}, nil, regexp.MustCompile(`^nothing$`))
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("filter kept an outbound it does not match: %v", filtered)
	}
	if logger.warnings != 1 {
		t.Fatalf("unexpected warning count: %d", logger.warnings)
	}
}
