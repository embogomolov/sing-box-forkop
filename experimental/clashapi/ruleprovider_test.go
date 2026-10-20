package clashapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

type testRuleProvider struct {
	adapter.RuleSet
	name       string
	snapshot   adapter.RuleSetProviderSnapshot
	callbacks  list.List[adapter.RuleSetUpdateCallback]
	registered chan struct{}
	access     sync.Mutex
}

func (p *testRuleProvider) Name() string {
	return p.name
}

func (p *testRuleProvider) ProviderSnapshot() adapter.RuleSetProviderSnapshot {
	p.access.Lock()
	defer p.access.Unlock()
	return p.snapshot
}

func (p *testRuleProvider) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	p.access.Lock()
	element := p.callbacks.PushBack(callback)
	p.access.Unlock()
	select {
	case p.registered <- struct{}{}:
	default:
	}
	return element
}

func (p *testRuleProvider) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	p.access.Lock()
	p.callbacks.Remove(element)
	p.access.Unlock()
}

func (p *testRuleProvider) Update() error {
	p.access.Lock()
	p.snapshot.Revision++
	p.snapshot.UpdatedAt = time.Now()
	callbacks := p.callbacks.Array()
	p.access.Unlock()
	for _, callback := range callbacks {
		callback(p)
	}
	return nil
}

type testRuleProviderRouter struct {
	adapter.Router
	ruleSets []adapter.RuleSet
}

func (r *testRuleProviderRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	for _, ruleSet := range r.ruleSets {
		if ruleSet.Name() == tag {
			return ruleSet, true
		}
	}
	return nil, false
}

func (r *testRuleProviderRouter) RuleSets() []adapter.RuleSet {
	return r.ruleSets
}

func TestRuleProviderAPI(t *testing.T) {
	provider := &testRuleProvider{
		name: "private",
		snapshot: adapter.RuleSetProviderSnapshot{
			Type:     C.RuleSetTypeRemote,
			Format:   C.RuleSetFormatText,
			Revision: 1,
			IPCIDR:   adapter.RuleSetIPCIDRExport{Digest: "private-digest", IPv4: []string{"192.0.2.0/24"}},
		},
		registered: make(chan struct{}, 1),
	}
	secondProvider := &testRuleProvider{
		name:     "second",
		snapshot: adapter.RuleSetProviderSnapshot{Revision: 4},
	}
	handler := ruleProviderRouter(&Server{router: &testRuleProviderRouter{ruleSets: []adapter.RuleSet{provider, secondProvider}}})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	var providers struct {
		Revision  uint64                          `json:"revision"`
		Providers map[string]ruleProviderResponse `json:"providers"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &providers))
	require.Equal(t, providers.Providers[provider.name].Revision+providers.Providers[secondProvider.name].Revision, providers.Revision)
	require.Equal(t, uint64(5), providers.Revision)
	require.Equal(t, "HTTP", providers.Providers[provider.name].VehicleType)
	require.Equal(t, C.RuleSetFormatText, providers.Providers[provider.name].Format)
	require.Equal(t, []string{"192.0.2.0/24"}, providers.Providers[provider.name].IPCIDR.IPv4)
	var raw struct {
		Providers map[string]struct {
			IPCIDR map[string]json.RawMessage `json:"ip_cidr"`
		} `json:"providers"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &raw))
	require.JSONEq(t, `"private-digest"`, string(raw.Providers[provider.name].IPCIDR["digest"]))

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private", nil))
	require.Equal(t, http.StatusOK, response.Code)

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/private", nil))
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, uint64(2), provider.ProviderSnapshot().Revision)

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/events?once=1&since=5", nil))
	var event ruleProviderEvent
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &event))
	require.Equal(t, uint64(6), event.Revision)
	<-provider.registered

	response = httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/events?once=1&since=6", nil))
		close(done)
	}()
	<-provider.registered
	require.NoError(t, provider.Update())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("long poll did not receive rule-set update")
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &event))
	require.Equal(t, provider.name, event.Name)
	require.Equal(t, uint64(7), event.Revision)
}

type testLocalRuleProvider struct {
	adapter.RuleSet
	name string
}

func (p *testLocalRuleProvider) Name() string {
	return p.name
}

type testFailingRuleProvider struct {
	adapter.RuleSet
	name    string
	updates atomic.Int32
}

func (p *testFailingRuleProvider) Name() string {
	return p.name
}

func (p *testFailingRuleProvider) Update() error {
	p.updates.Add(1)
	return E.New("origin unreachable")
}

func TestUpdateAllRuleProviders(t *testing.T) {
	first := &testRuleProvider{name: "first"}
	second := &testRuleProvider{name: "second"}
	local := &testLocalRuleProvider{name: "local"}
	handler := ruleProviderRouter(&Server{router: &testRuleProviderRouter{
		ruleSets: []adapter.RuleSet{first, local, second},
	}})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/", nil))
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, uint64(1), first.ProviderSnapshot().Revision)
	require.Equal(t, uint64(1), second.ProviderSnapshot().Revision)
}

func TestUpdateAllRuleProvidersReportsFailuresAfterUpdatingTheRest(t *testing.T) {
	healthy := &testRuleProvider{name: "healthy"}
	broken := &testFailingRuleProvider{name: "broken"}
	handler := ruleProviderRouter(&Server{router: &testRuleProviderRouter{
		ruleSets: []adapter.RuleSet{broken, healthy},
	}})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	var failure HTTPError
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
	require.Contains(t, failure.Message, "update 1 of 2 rule-sets failed")
	require.Contains(t, failure.Message, "broken")
	require.Contains(t, failure.Message, "origin unreachable")
	require.Equal(t, int32(1), broken.updates.Load())
	// A failing rule-set must not stop the others from being refreshed.
	require.Equal(t, uint64(1), healthy.ProviderSnapshot().Revision)
}
