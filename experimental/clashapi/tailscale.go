package clashapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func tailscaleRouter(endpointManager adapter.EndpointManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getTailscaleStatus(endpointManager))
	r.Get("/{tag}/ping", pingTailscalePeer(endpointManager))
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

type tailscalePinger interface {
	StartTailscalePing(ctx context.Context, peerIP string, fn func(*adapter.TailscalePingResult)) error
}

func pingTailscalePeer(endpointManager adapter.EndpointManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		query := r.URL.Query()
		address, err := netip.ParseAddr(query.Get("address"))
		timeout, timeoutErr := strconv.ParseInt(query.Get("timeout"), 10, 32)
		if err != nil || timeoutErr != nil || timeout <= 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		var pinger tailscalePinger
		if endpointManager != nil {
			endpoint, _ := endpointManager.Get(getEscapeParam(r, "tag"))
			pinger, _ = endpoint.(tailscalePinger)
		}
		if pinger == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
		defer cancel()
		// The endpoint pings once a second until the context ends: the first answer is the one.
		var result *adapter.TailscalePingResult
		err = pinger.StartTailscalePing(ctx, address.String(), func(pingResult *adapter.TailscalePingResult) {
			result = pingResult
			cancel()
		})

		switch {
		case result != nil && result.Error == "":
			render.JSON(w, r, render.M{"latency": result.LatencyMs})
		case result != nil:
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(result.Error))
		case errors.Is(err, context.DeadlineExceeded):
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
		default:
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
		}
	}
}
