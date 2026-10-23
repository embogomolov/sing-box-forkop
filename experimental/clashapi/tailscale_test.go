package clashapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type tailscaleTestEndpoint struct {
	adapter.Endpoint
	status adapter.TailscaleStatus
}

func (e *tailscaleTestEndpoint) TailscaleStatus() adapter.TailscaleStatus { return e.status }

type tailscaleTestEndpointManager struct {
	adapter.EndpointManager
	endpoints []adapter.Endpoint
	tagged    map[string]adapter.Endpoint
}

func (m *tailscaleTestEndpointManager) Endpoints() []adapter.Endpoint { return m.endpoints }

func (m *tailscaleTestEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.tagged[tag]
	return endpoint, loaded
}

type tailscalePingTestEndpoint struct {
	adapter.Endpoint
	ping   func(ctx context.Context, fn func(*adapter.TailscalePingResult)) error
	peerIP string
}

func (e *tailscalePingTestEndpoint) StartTailscalePing(ctx context.Context, peerIP string, fn func(*adapter.TailscalePingResult)) error {
	e.peerIP = peerIP
	return e.ping(ctx, fn)
}

// answering pings as the endpoint does: an answer each second until the context ends.
func answering(answer adapter.TailscalePingResult) func(context.Context, func(*adapter.TailscalePingResult)) error {
	return func(ctx context.Context, fn func(*adapter.TailscalePingResult)) error {
		for {
			result := answer
			fn(&result)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
}

func silent(ctx context.Context, _ func(*adapter.TailscalePingResult)) error {
	<-ctx.Done()
	return ctx.Err()
}

func pingTailscale(t *testing.T, manager adapter.EndpointManager, path string) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	tailscaleRouter(manager).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Code, body
}

func getTailscale(t *testing.T, manager adapter.EndpointManager) map[string][]map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	tailscaleRouter(manager).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string][]map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTailscaleReportsOnlyTailscaleEndpoints(t *testing.T) {
	manager := &tailscaleTestEndpointManager{endpoints: []adapter.Endpoint{
		&tailscaleTestEndpoint{status: adapter.TailscaleStatus{
			Tag:       "tailnet",
			State:     "Running",
			Connected: true,
			Name:      "router",
			Addresses: []string{"100.64.0.1"},
			Routes:    []adapter.TailscaleRouteStatus{{Prefix: "192.168.1.0/24", Approved: true}},
			Health:    []string{},
			ExitNode:  "phone",
			Peers: []adapter.TailscalePeerStatus{{
				Name: "phone", Addresses: []string{"100.64.0.2"}, Subnets: []string{"10.1.0.0/16"}, Online: true,
				ExitNodeOption: true, ExitNode: true,
			}},
		}},
		struct{ adapter.Endpoint }{},
	}}
	endpoints := getTailscale(t, manager)["endpoints"]
	if len(endpoints) != 1 {
		t.Fatalf("want the one Tailscale endpoint, got %v", endpoints)
	}
	endpoint := endpoints[0]
	if endpoint["tag"] != "tailnet" || endpoint["state"] != "Running" || endpoint["connected"] != true || endpoint["name"] != "router" ||
		endpoint["exitNode"] != "phone" {
		t.Fatalf("unexpected endpoint %v", endpoint)
	}
	route := endpoint["routes"].([]any)[0].(map[string]any)
	if route["prefix"] != "192.168.1.0/24" || route["approved"] != true {
		t.Fatalf("unexpected route %v", route)
	}
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	if peer["name"] != "phone" || peer["online"] != true || peer["exitNodeOption"] != true || peer["exitNode"] != true ||
		peer["subnets"].([]any)[0] != "10.1.0.0/16" {
		t.Fatalf("unexpected peer %v", peer)
	}
}

func TestTailscaleReportsAnEmptyListWithoutEndpoints(t *testing.T) {
	endpoints, loaded := getTailscale(t, &tailscaleTestEndpointManager{})["endpoints"]
	if !loaded || endpoints == nil || len(endpoints) != 0 {
		t.Fatalf("want an empty list, got %v", endpoints)
	}
}

func TestTailscalePingAnswersWithTheFirstPong(t *testing.T) {
	endpoint := &tailscalePingTestEndpoint{ping: answering(adapter.TailscalePingResult{
		LatencyMs: 12.5, IsDirect: true, Endpoint: "203.0.113.7:41641",
	})}
	manager := &tailscaleTestEndpointManager{tagged: map[string]adapter.Endpoint{"home/tailnet": endpoint}}
	start := time.Now()
	status, body := pingTailscale(t, manager, "/home%2Ftailnet/ping?address=100.64.0.2&timeout=5000")
	if status != http.StatusOK || body["latency"] != 12.5 || endpoint.peerIP != "100.64.0.2" {
		t.Fatalf("unexpected answer %d %v to %q", status, body, endpoint.peerIP)
	}
	if waited := time.Since(start); waited >= time.Second {
		t.Fatalf("waited %v for a second pong", waited)
	}

	status, body = pingTailscale(t, manager, "/home%2Ftailnet/ping?address=fd7a%3A115c%3Aa1e0%3A%3A2&timeout=5000")
	if status != http.StatusOK || endpoint.peerIP != "fd7a:115c:a1e0::2" {
		t.Fatalf("unexpected answer %d %v to %q", status, body, endpoint.peerIP)
	}
}

func TestTailscalePingReportsAFailureAndASilence(t *testing.T) {
	endpoint := &tailscalePingTestEndpoint{ping: answering(adapter.TailscalePingResult{Error: "no matching peer"})}
	manager := &tailscaleTestEndpointManager{tagged: map[string]adapter.Endpoint{"tailnet": endpoint}}
	status, body := pingTailscale(t, manager, "/tailnet/ping?address=100.64.0.9&timeout=5000")
	if status != http.StatusServiceUnavailable || body["message"] != "no matching peer" {
		t.Fatalf("unexpected answer %d %v", status, body)
	}

	endpoint.ping = silent
	status, body = pingTailscale(t, manager, "/tailnet/ping?address=100.64.0.9&timeout=50")
	if status != http.StatusGatewayTimeout || body["message"] != ErrRequestTimeout.Message {
		t.Fatalf("unexpected answer %d %v", status, body)
	}
}

func TestTailscalePingRefusesWhatItCannotPing(t *testing.T) {
	manager := &tailscaleTestEndpointManager{tagged: map[string]adapter.Endpoint{
		"home/tailnet": &tailscalePingTestEndpoint{ping: silent},
		"home/wg":      struct{ adapter.Endpoint }{},
	}}
	for path, want := range map[string]int{
		"/home%2Fother/ping?address=100.64.0.2&timeout=5000": http.StatusNotFound,
		"/home%2Fwg/ping?address=100.64.0.2&timeout=5000":    http.StatusNotFound,
		"/home%2Ftailnet/ping?address=phone&timeout=5000":    http.StatusBadRequest,
		"/home%2Ftailnet/ping?address=100.64.0.2":            http.StatusBadRequest,
		"/home%2Ftailnet/ping?address=100.64.0.2&timeout=0":  http.StatusBadRequest,
	} {
		if status, body := pingTailscale(t, manager, path); status != want {
			t.Errorf("%s: want %d, got %d %v", path, want, status, body)
		}
	}
	if status, _ := pingTailscale(t, &tailscaleTestEndpointManager{}, "/tailnet/ping?address=100.64.0.2&timeout=5000"); status != http.StatusNotFound {
		t.Fatalf("a core without endpoints answered %d", status)
	}
}
