package rule

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type missingDetourOutboundManager struct {
	adapter.OutboundManager
	defaultCalls int
}

func (m *missingDetourOutboundManager) Outbound(string) (adapter.Outbound, bool) { return nil, false }
func (m *missingDetourOutboundManager) Default() adapter.Outbound {
	m.defaultCalls++
	return nil
}

type recordingDetour struct {
	adapter.Outbound
	dialCalls int
}

func (d *recordingDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialCalls++
	return new(net.Dialer).DialContext(ctx, network, destination.String())
}

type recordingDetourOutboundManager struct {
	adapter.OutboundManager
	detour       adapter.Outbound
	defaultCalls int
}

func (m *recordingDetourOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.detour, tag == "proxy"
}

func (m *recordingDetourOutboundManager) Default() adapter.Outbound {
	m.defaultCalls++
	return nil
}

type savedRuleSetCacheFile struct {
	adapter.CacheFile
	saved *adapter.SavedBinary
}

func (c *savedRuleSetCacheFile) LoadRuleSet(string) *adapter.SavedBinary {
	return c.saved
}

func (c *savedRuleSetCacheFile) SaveRuleSet(_ string, saved *adapter.SavedBinary) error {
	c.saved = saved
	return nil
}

func TestRemoteRuleSetMissingDetourDoesNotFallbackOrFailStartup(t *testing.T) {
	manager := new(missingDetourOutboundManager)
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := newRemoteDownloadForTest(t, ctx, option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    []string{"missing-detour"},
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            "https://example.com/rules",
			DownloadDetour: "proxy",
			UpdateInterval: badoption.Duration(time.Hour),
		},
	})
	if err := ruleSet.StartContext(ctx, adapter.NewHTTPStartContext()); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if manager.defaultCalls != 0 {
		t.Fatal("missing download detour fell back to the default outbound")
	}
}

func TestRemoteAutoRuleSetUsesConfiguredDetour(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "example.com\n192.0.2.0/24\n")
	}))
	defer server.Close()

	detour := new(recordingDetour)
	manager := &recordingDetourOutboundManager{detour: detour}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	startContext := adapter.NewHTTPStartContext()
	defer startContext.Close()
	ruleSet := newRemoteDownloadForTest(t, ctx, option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    []string{"detoured-auto"},
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
		},
	})
	if err := ruleSet.StartContext(ctx, startContext); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if detour.dialCalls == 0 || manager.defaultCalls != 0 || ruleSet.revision != 1 {
		t.Fatalf("unexpected detour fetch: dial=%d default=%d revision=%d", detour.dialCalls, manager.defaultCalls, ruleSet.revision)
	}
	snapshot := ruleSet.ProviderSnapshot()
	if len(snapshot.IPCIDR.IPv4) != 1 || snapshot.IPCIDR.IPv4[0] != "192.0.2.0/24" {
		t.Fatalf("unexpected text CIDR export: %v", snapshot.IPCIDR.IPv4)
	}
	if snapshot.Format != C.RuleSetFormatText {
		t.Fatalf("reported format %q instead of the detected text format", snapshot.Format)
	}
}

func TestRemoteRuleSetHTTPFailureDoesNotFailStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := newRemoteDownloadForTest(t, ctx, option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    []string{"unavailable"},
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
			UpdateInterval: badoption.Duration(time.Hour),
		},
	})
	if err := ruleSet.StartContext(ctx, adapter.NewHTTPStartContext()); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if ruleSet.revision != 0 {
		t.Fatal("unavailable remote rule-set became active")
	}
}

func TestRemoteRuleSetMalformedDownloadDoesNotFailStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "{")
	}))
	defer server.Close()
	manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := newRemoteDownloadForTest(t, ctx, option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    []string{"malformed"},
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
			UpdateInterval: badoption.Duration(time.Hour),
		},
	})
	defer ruleSet.Close()
	if err := ruleSet.StartContext(ctx, adapter.NewHTTPStartContext()); err != nil {
		t.Fatal(err)
	}
	if ruleSet.revision != 0 {
		t.Fatal("malformed remote rule-set became active")
	}
}

func TestRemoteRuleSetRefetchesCacheOfAnotherURL(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(response, "fetched.example\n")
	}))
	defer server.Close()
	for _, testCase := range []struct {
		name      string
		cachedURL string
		requests  int32
	}{
		{name: "same URL", cachedURL: server.URL, requests: 0},
		{name: "another URL", cachedURL: "https://example.com/old", requests: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			requests.Store(0)
			urlHash := sha256.Sum256([]byte(testCase.cachedURL))
			cacheFile := &savedRuleSetCacheFile{saved: &adapter.SavedBinary{
				Content:     []byte("cached.example\n"),
				LastUpdated: time.Now(),
				URLHash:     urlHash[:],
			}}
			manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
			ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
			ctx = service.ContextWith[adapter.CacheFile](ctx, cacheFile)
			ruleSet := newRemoteDownloadForTest(t, ctx, option.RuleSet{
				Type:   C.RuleSetTypeRemote,
				Tag:    []string{"cached"},
				Format: C.RuleSetFormatAuto,
				RemoteOptions: option.RemoteRuleSet{
					URL:            server.URL,
					DownloadDetour: "proxy",
				},
			})
			defer ruleSet.Close()
			if err := ruleSet.StartContext(ctx, adapter.NewHTTPStartContext()); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != testCase.requests {
				t.Fatalf("cache of %s led to %d downloads", testCase.cachedURL, requests.Load())
			}
		})
	}
}

func TestRemoteRuleSetKeepsLastValidRulesOnParseFailure(t *testing.T) {
	ruleSet := &RemoteRuleSet{
		ctx: context.Background(),
		options: option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"preserve"},
			Format: C.RuleSetFormatAuto,
		},
	}
	if err := ruleSet.loadBytes([]byte("example.com\n"), time.Now(), "valid"); err != nil {
		t.Fatal(err)
	}
	if err := ruleSet.loadBytes([]byte("{"), time.Now(), "invalid"); err == nil {
		t.Fatal("expected invalid refresh to fail")
	}
	if ruleSet.revision != 1 || ruleSet.lastEtag != "valid" || len(ruleSet.rules) == 0 {
		t.Fatal("invalid refresh replaced the last valid rule-set")
	}
}

func TestRemoteRuleSetCloseWaitsForUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ruleSet := &RemoteRuleSet{ctx: ctx, cancel: cancel, rules: []adapter.HeadlessRule{nil}}
	ruleSet.updateAccess.Lock()
	done := make(chan struct{})
	go func() {
		_ = ruleSet.Close()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("rule-set closed while an update was still publishing")
	case <-time.After(50 * time.Millisecond):
	}
	ruleSet.updateAccess.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rule-set close did not finish after the update completed")
	}
	if len(ruleSet.rules) != 0 {
		t.Fatal("rule-set update survived close")
	}
	if _, err := ruleSet.fetch(context.Background(), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("rule-set accepted an update after close: %v", err)
	}
}

func TestRemoteRuleSetWithoutUpdateIntervalIsNotScheduled(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(response, "example.com\n")
	}))
	defer server.Close()
	manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	newRuleSet := func(tag string, updateInterval time.Duration) *RemoteRuleSet {
		return newRemoteDownloadForTest(t, ctx, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{tag},
			Format: C.RuleSetFormatAuto,
			RemoteOptions: option.RemoteRuleSet{
				URL:            server.URL,
				DownloadDetour: "proxy",
				UpdateInterval: badoption.Duration(updateInterval),
			},
		})
	}
	manual := newRuleSet("manual", 0)
	defer manual.Close()
	scheduled := newRuleSet("scheduled", time.Hour)
	defer scheduled.Close()
	if updater := NewRuleSetUpdater(ctx, []adapter.RuleSet{manual}); updater != nil {
		t.Fatal("a rule-set without update_interval was scheduled")
	}
	updater := NewRuleSetUpdater(ctx, []adapter.RuleSet{manual, scheduled})
	if updater == nil || len(updater.ruleSets) != 1 || updater.ruleSets[0] != scheduled {
		t.Fatal("only the rule-set with update_interval must be scheduled")
	}
	if err := manual.StartContext(ctx, adapter.NewHTTPStartContext()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || manual.revision != 1 {
		t.Fatalf("initial download did not happen exactly once: requests=%d revision=%d", requests.Load(), manual.revision)
	}
	if err := manual.Update(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || manual.revision != 2 {
		t.Fatalf("explicit update was not applied: requests=%d revision=%d", requests.Load(), manual.revision)
	}
}

func newRemoteDownloadForTest(t *testing.T, ctx context.Context, options option.RuleSet) *RemoteRuleSet {
	t.Helper()
	manager := &ruleSetHTTPClientManager{outbound: service.FromContext[adapter.OutboundManager](ctx)}
	ctx = service.ContextWith[adapter.HTTPClientManager](ctx, manager)
	ruleSet, err := NewRemoteRuleSet(ctx, logger.NOP(), options.Tag[0], options)
	if err != nil {
		t.Fatal(err)
	}
	return ruleSet
}

type ruleSetHTTPClientManager struct {
	adapter.HTTPClientManager
	outbound adapter.OutboundManager
}

type ruleSetHTTPTransport struct{ *http.Transport }

func (t *ruleSetHTTPTransport) Reset() { t.CloseIdleConnections() }

func (m *ruleSetHTTPClientManager) ResolveTransport(_ context.Context, _ logger.ContextLogger, options option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	return &ruleSetHTTPTransport{&http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		outbound, found := m.outbound.Outbound(options.Detour)
		if !found {
			return nil, errors.New("configured detour unavailable")
		}
		return outbound.DialContext(ctx, network, M.ParseSocksaddr(address))
	}}}, nil
}
