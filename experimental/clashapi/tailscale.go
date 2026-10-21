package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func tailscaleRouter(endpointManager adapter.EndpointManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getTailscaleStatus(endpointManager))
	return r
}

func getTailscaleStatus(endpointManager adapter.EndpointManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		endpoints := []adapter.TailscaleStatus{}
		if endpointManager != nil {
			for _, endpoint := range endpointManager.Endpoints() {
				if reporter, isTailscale := endpoint.(adapter.TailscaleStatusReporter); isTailscale {
					endpoints = append(endpoints, reporter.TailscaleStatus())
				}
			}
		}
		render.JSON(w, r, render.M{"endpoints": endpoints})
	}
}
