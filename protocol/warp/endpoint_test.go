package warp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func validWARPTestConfig(t *testing.T) *Config {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{PrivateKey: key.String()}
	config.Interface.Addresses.V4 = "172.16.0.2"
	config.Interface.Addresses.V6 = "2606:4700:110:8765::2"
	config.Peers = make([]cloudflare.Peer, 1)
	config.Peers[0].PublicKey = key.PublicKey().String()
	config.Peers[0].Endpoint.Host = "engage.cloudflareclient.com"
	config.Peers[0].Endpoint.Ports = []int{2408}
	return config
}

func TestWARPConfigValidation(t *testing.T) {
	if err := validateConfig(validWARPTestConfig(t)); err != nil {
		t.Fatalf("valid WARP config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "empty private key", mutate: func(config *Config) { config.PrivateKey = "" }},
		{name: "empty peers", mutate: func(config *Config) { config.Peers = nil }},
		{name: "empty ports", mutate: func(config *Config) { config.Peers[0].Endpoint.Ports = nil }},
		{name: "invalid IPv4 address", mutate: func(config *Config) { config.Interface.Addresses.V4 = "not-an-ip" }},
		{name: "invalid IPv6 address", mutate: func(config *Config) { config.Interface.Addresses.V6 = "not-an-ip" }},
		{name: "empty peer key", mutate: func(config *Config) { config.Peers[0].PublicKey = "" }},
		{name: "invalid peer key", mutate: func(config *Config) { config.Peers[0].PublicKey = "invalid" }},
		{name: "empty peer host", mutate: func(config *Config) { config.Peers[0].Endpoint.Host = "" }},
		{name: "invalid port", mutate: func(config *Config) { config.Peers[0].Endpoint.Ports = []int{0} }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validWARPTestConfig(t)
			testCase.mutate(config)
			if err := validateConfig(config); err == nil {
				t.Fatal("invalid WARP config was accepted")
			}
		})
	}
}

func TestWARPProfileCacheIdentity(t *testing.T) {
	base := option.CloudflareProfile{ID: "id", AuthToken: "token", PrivateKey: "key"}
	baseKey := warpCacheKey("warp", base)
	for name, profile := range map[string]option.CloudflareProfile{
		"id":          {ID: "other", AuthToken: "token", PrivateKey: "key"},
		"auth token":  {ID: "id", AuthToken: "other", PrivateKey: "key"},
		"private key": {ID: "id", AuthToken: "token", PrivateKey: "other"},
		"license key": {ID: "id", AuthToken: "token", PrivateKey: "key", LicenseKey: "license"},
	} {
		if warpCacheKey("warp", profile) == baseKey {
			t.Fatalf("%s did not affect WARP cache identity", name)
		}
	}
	if warpCacheKey("warp", option.CloudflareProfile{}) != "warp" {
		t.Fatal("automatic WARP profile did not retain the stable cache key")
	}
	if warpCacheKey("warp", option.CloudflareProfile{LicenseKey: "license"}) == "warp" {
		t.Fatal("WARP license key did not bypass an unrelated cached profile")
	}
}

func TestWARPEndpointRejectsPartialProfileCredentials(t *testing.T) {
	for _, profile := range []option.CloudflareProfile{
		{ID: "id"},
		{ID: "id", AuthToken: "token"},
		{PrivateKey: "key"},
	} {
		if _, err := NewEndpoint(context.Background(), nil, nil, "warp", option.WARPEndpointOptions{Profile: profile}); err == nil {
			t.Fatal("partial WARP profile credentials were accepted")
		}
	}
}

func TestWARPPeerAddress(t *testing.T) {
	for input, expected := range map[string]string{
		"engage.cloudflareclient.com":      "engage.cloudflareclient.com",
		"engage.cloudflareclient.com:2408": "engage.cloudflareclient.com",
		"2606:4700:d0::a29f:c001":          "2606:4700:d0::a29f:c001",
		"[2606:4700:d0::a29f:c001]:2408":   "2606:4700:d0::a29f:c001",
	} {
		if actual := warpPeerAddress(input); actual != expected {
			t.Fatalf("warpPeerAddress(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func newLifecycleTestEndpoint() (*Endpoint, *adapter.Scope) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.NewNOPFactory().NewLogger("warp")
	endpoint := &Endpoint{
		ctx:    ctx,
		logger: logger,
		cancel: cancel,
		await:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	return endpoint, adapter.NewScope(context.Background(), logger)
}

func TestWARPEndpointStartsAtPostStart(t *testing.T) {
	endpoint, scope := newLifecycleTestEndpoint()
	started := make(chan struct{})
	endpoint.startHandler = func(*adapter.Scope) {
		close(started)
		endpoint.release()
	}

	if err := endpoint.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("WARP initialization started before StartStatePostStart")
	case <-time.After(50 * time.Millisecond):
	}
	if err := endpoint.Start(adapter.StartStatePostStart, scope); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("WARP initialization did not start during StartStatePostStart")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWARPEndpointCloseBeforeStart(t *testing.T) {
	endpoint, scope := newLifecycleTestEndpoint()
	if err := endpoint.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- scope.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WARP close blocked before initialization started")
	}
}

func TestWARPEndpointCloseCancelsInitialization(t *testing.T) {
	endpoint, scope := newLifecycleTestEndpoint()
	endpoint.startHandler = func(*adapter.Scope) {
		defer endpoint.release()
		<-endpoint.ctx.Done()
	}

	if err := endpoint.Start(adapter.StartStatePostStart, scope); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- scope.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WARP close did not cancel initialization")
	}
}

func newProfileRetryTestEndpoint(t *testing.T) *Endpoint {
	t.Helper()
	initialDelay, maxDelay := profileRetryInitialDelay, profileRetryMaxDelay
	profileRetryInitialDelay, profileRetryMaxDelay = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { profileRetryInitialDelay, profileRetryMaxDelay = initialDelay, maxDelay })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Endpoint{ctx: ctx, cancel: cancel, await: make(chan struct{}), done: make(chan struct{})}
}

func TestWARPProfileFetchRetriesUntilValid(t *testing.T) {
	endpoint := newProfileRetryTestEndpoint(t)
	valid := validWARPTestConfig(t)
	invalid := validWARPTestConfig(t)
	invalid.Peers = nil
	attempts := 0
	config := endpoint.fetchConfig(log.NewNOPFactory().NewLogger("warp"), func() (*Config, error) {
		attempts++
		switch attempts {
		case 1:
			return nil, errors.New("TLS handshake timeout")
		case 2:
			return invalid, nil
		}
		return valid, nil
	})
	if config != valid || attempts != 3 {
		t.Fatalf("got profile %p after %d attempts, want the valid one after 3", config, attempts)
	}
}

func TestWARPProfileRetryFailsDialsAndStopsOnClose(t *testing.T) {
	endpoint := newProfileRetryTestEndpoint(t)
	failed := make(chan struct{}, 1)
	result := make(chan *Config, 1)
	go func() {
		result <- endpoint.fetchConfig(log.NewNOPFactory().NewLogger("warp"), func() (*Config, error) {
			select {
			case failed <- struct{}{}:
			default:
			}
			return nil, errors.New("connection refused")
		})
	}()
	<-failed

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := endpoint.initializedEndpoint(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a dial while the profile retries got %v, want an immediate failure", err)
	}

	endpoint.cancel()
	select {
	case config := <-result:
		if config != nil {
			t.Fatal("a closed endpoint returned a profile")
		}
	case <-time.After(time.Second):
		t.Fatal("profile retries did not stop when the endpoint closed")
	}
}

// A URL test warms the WireGuard session up, also before the profile has brought the endpoint up.
func TestWARPEndpointReportsWireGuardSession(t *testing.T) {
	multiplexOutbound, isMultiplex := common.Cast[adapter.OutboundWithMultiplex](&Endpoint{})
	if !isMultiplex || !multiplexOutbound.MultiplexEnabled() {
		t.Fatal("WARP did not report its WireGuard session")
	}
}
