package clashapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
}

func (m *tailscaleTestEndpointManager) Endpoints() []adapter.Endpoint { return m.endpoints }

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
			Peers: []adapter.TailscalePeerStatus{{
				Name: "phone", Addresses: []string{"100.64.0.2"}, Online: true, ExitNodeOption: true,
			}},
		}},
		struct{ adapter.Endpoint }{},
	}}
	endpoints := getTailscale(t, manager)["endpoints"]
	if len(endpoints) != 1 {
		t.Fatalf("want the one Tailscale endpoint, got %v", endpoints)
	}
	endpoint := endpoints[0]
	if endpoint["tag"] != "tailnet" || endpoint["state"] != "Running" || endpoint["connected"] != true || endpoint["name"] != "router" {
		t.Fatalf("unexpected endpoint %v", endpoint)
	}
	route := endpoint["routes"].([]any)[0].(map[string]any)
	if route["prefix"] != "192.168.1.0/24" || route["approved"] != true {
		t.Fatalf("unexpected route %v", route)
	}
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	if peer["name"] != "phone" || peer["online"] != true || peer["exitNodeOption"] != true {
		t.Fatalf("unexpected peer %v", peer)
	}
}

func TestTailscaleReportsAnEmptyListWithoutEndpoints(t *testing.T) {
	endpoints, loaded := getTailscale(t, &tailscaleTestEndpointManager{})["endpoints"]
	if !loaded || endpoints == nil || len(endpoints) != 0 {
		t.Fatalf("want an empty list, got %v", endpoints)
	}
}
