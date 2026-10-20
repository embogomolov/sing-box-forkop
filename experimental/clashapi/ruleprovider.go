package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/batch"
	F "github.com/sagernet/sing/common/format"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// ruleProviderUpdateConcurrency bounds the parallel downloads started by a
// bulk update, so refreshing every rule-set at once stays usable on routers.
const ruleProviderUpdateConcurrency = 5

type ruleProviderResponse struct {
	Type        string                      `json:"type"`
	VehicleType string                      `json:"vehicleType"`
	Name        string                      `json:"name"`
	Format      string                      `json:"format,omitempty"`
	UpdatedAt   time.Time                   `json:"updatedAt"`
	Revision    uint64                      `json:"revision"`
	IPCIDR      adapter.RuleSetIPCIDRExport `json:"ip_cidr"`
}

type ruleProviderEvent struct {
	Name     string `json:"name,omitempty"`
	Revision uint64 `json:"revision"`
}

func ruleProviderRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders(server))
	r.Put("/", updateRuleProviders(server))
	r.Get("/events", watchRuleProviders(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findRuleProviderByName(server))
		r.Get("/", getRuleProvider)
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSets := server.router.RuleSets()
		providers := make(render.M, len(ruleSets))
		var revision uint64
		for _, ruleSet := range ruleSets {
			provider := ruleProviderInfo(ruleSet)
			providers[ruleSet.Name()] = provider
			revision += provider.Revision
		}
		render.JSON(w, r, render.M{
			"providers": providers,
			"revision":  revision,
		})
	}
}

func getRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyRuleProvider).(adapter.RuleSet)
	render.JSON(w, r, ruleProviderInfo(ruleSet))
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyRuleProvider).(adapter.RuleSet)
	if updater, isUpdater := ruleSet.(adapter.RuleSetUpdater); isUpdater {
		if err := updater.Update(); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}
	render.NoContent(w, r)
}

// updateRuleProviders updates every updatable rule-set at once, so a client does
// not have to enumerate them and issue one request per rule-set.
func updateRuleProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		updateBatch, _ := batch.New(r.Context(), batch.WithConcurrencyNum[any](ruleProviderUpdateConcurrency))
		for _, ruleSet := range server.router.RuleSets() {
			updater, isUpdater := ruleSet.(adapter.RuleSetUpdater)
			if !isUpdater {
				continue
			}
			updateBatch.Go(ruleSet.Name(), func() (any, error) {
				return nil, updater.Update()
			})
		}
		results, updateErr := updateBatch.WaitAndGetResult()
		if updateErr == nil {
			render.NoContent(w, r)
			return
		}
		failed := make([]string, 0, len(results))
		for name, result := range results {
			if result.Err != nil {
				failed = append(failed, name)
			}
		}
		sort.Strings(failed)
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(F.ToString(
			"update ", len(failed), " of ", len(results), " rule-sets failed: ",
			strings.Join(failed, ", "), ": ", updateErr.Err,
		)))
	}
}

func findRuleProviderByName(server *Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			ruleSet, exists := server.router.RuleSet(name)
			if !exists {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyRuleProvider, ruleSet)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ruleProviderInfo(ruleSet adapter.RuleSet) ruleProviderResponse {
	var snapshot adapter.RuleSetProviderSnapshot
	if provider, loaded := ruleSet.(adapter.RuleSetProvider); loaded {
		snapshot = provider.ProviderSnapshot()
	}
	return ruleProviderResponse{
		Type:        "Rule",
		VehicleType: ruleProviderVehicleType(snapshot.Type),
		Name:        ruleSet.Name(),
		Format:      snapshot.Format,
		UpdatedAt:   snapshot.UpdatedAt,
		Revision:    snapshot.Revision,
		IPCIDR:      snapshot.IPCIDR,
	}
}

func ruleProviderVehicleType(providerType string) string {
	switch providerType {
	case C.RuleSetTypeRemote:
		return "HTTP"
	case C.RuleSetTypeLocal:
		return "File"
	default:
		return "Compatible"
	}
}

func ruleProviderRevision(ruleSets []adapter.RuleSet) uint64 {
	var revision uint64
	for _, ruleSet := range ruleSets {
		if provider, loaded := ruleSet.(adapter.RuleSetProvider); loaded {
			revision += provider.ProviderSnapshot().Revision
		}
	}
	return revision
}

func watchRuleProviders(server *Server) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSets := server.router.RuleSets()
		events := make(chan ruleProviderEvent, max(1, len(ruleSets)))
		for _, ruleSet := range ruleSets {
			element := ruleSet.RegisterCallback(func(updated adapter.RuleSet) {
				event := ruleProviderEvent{Name: updated.Name(), Revision: ruleProviderRevision(ruleSets)}
				select {
				case events <- event:
				default:
				}
			})
			defer ruleSet.UnregisterCallback(element)
		}

		current := ruleProviderEvent{Revision: ruleProviderRevision(ruleSets)}
		since, err := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		if err != nil && r.URL.Query().Get("since") != "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if current.Revision != since {
			render.JSON(w, r, current)
			return
		}
		select {
		case event := <-events:
			render.JSON(w, r, event)
		case <-r.Context().Done():
		}
	}
}
