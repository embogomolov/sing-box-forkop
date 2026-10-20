package provider

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxProvider "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type subscriptionCacheRecorder struct {
	adapter.CacheFile
	enabled  bool
	savedTag string
	saved    *adapter.SavedBinary
}

func (c *subscriptionCacheRecorder) StoreSubscriptions() bool { return c.enabled }
func (c *subscriptionCacheRecorder) SaveSubscription(tag string, saved *adapter.SavedBinary) error {
	c.savedTag, c.saved = tag, saved
	return nil
}

func TestStoreSubscriptionsControlsWrites(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cache := &subscriptionCacheRecorder{enabled: enabled}
		remote := &ProviderRemote{cacheFile: cache, rawContent: "subscription"}
		remote.saveProviderCache()
		if (cache.saved != nil) != enabled {
			t.Fatalf("store_subscriptions=%v: wrote cache=%v", enabled, cache.saved != nil)
		}
	}
}

func TestProviderCacheIsKeyedByTagAndCheckedBySource(t *testing.T) {
	headers := http.Header{"X-Token": {"one"}}
	cache := &subscriptionCacheRecorder{enabled: true}
	remote := &ProviderRemote{
		ctx:        context.Background(),
		logger:     log.NewNOPFactory().NewLogger("test"),
		cacheFile:  cache,
		url:        "https://example.com/sub",
		userAgent:  "sing-box",
		headers:    headers,
		rawContent: "subscription",
	}
	remote.Adapter = boxProvider.NewAdapter(context.Background(), nil, nil, log.NewNOPFactory(), remote.logger, "provider", C.ProviderTypeRemote, option.ProviderHealthCheckOptions{})
	remote.subscriptionInfo = adapter.SubscriptionInfo{Total: 10}
	remote.saveProviderCache()
	if cache.savedTag != "provider" || !bytes.Equal(cache.saved.URLHash, providerCacheIdentity(remote.url, remote.userAgent, headers)) {
		t.Fatalf("provider cache saved under %q with identity %x", cache.savedTag, cache.saved.URLHash)
	}

	moved := &ProviderRemote{
		ctx:       context.Background(),
		logger:    log.NewNOPFactory().NewLogger("test"),
		url:       "https://example.com/other",
		userAgent: "sing-box",
		headers:   headers,
	}
	moved.restoreProviderCache(cache.saved)
	if moved.SubscriptionInfo().Total != 0 {
		t.Fatal("a provider restored the cache of another source")
	}
}
