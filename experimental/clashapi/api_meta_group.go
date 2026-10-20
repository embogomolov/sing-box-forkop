package clashapi

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const groupDelayConcurrency = 10

// Members measured within this window go to the back of the next sweep, so a
// second press continues through the group; older measurements are equally
// stale and keep the group's own order.
const groupDelayFreshWindow = time.Minute

// The request timeout is the budget of the whole sweep, so a single member gets
// at most this and a few dead nodes cannot hold every slot until it runs out.
const groupDelayNodeTimeout = 5 * time.Second

func groupRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getGroups(server))
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getGroup(server))
		r.Get("/delay", getGroupDelay(server))
	})
	return r
}

func getGroups(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups := common.Map(common.Filter(server.outbound.Outbounds(), func(it adapter.Outbound) bool {
			_, isGroup := it.(adapter.OutboundGroup)
			return isGroup
		}), func(it adapter.Outbound) *badjson.JSONObject {
			return proxyInfo(server, it)
		})
		render.JSON(w, r, render.M{
			"proxies": groups,
		})
	}
}

func getGroup(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		if _, ok := proxy.(adapter.OutboundGroup); ok {
			render.JSON(w, r, proxyInfo(server, proxy))
			return
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

func getGroupDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		outboundGroup, ok := proxy.(adapter.OutboundGroup)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 32)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(server.ctx, time.Millisecond*time.Duration(timeout))
		defer cancel()

		var result map[string]uint16
		if urlTestGroup, isURLTestGroup := outboundGroup.(adapter.URLTestGroup); isURLTestGroup {
			result, err = urlTestGroup.URLTest(ctx)
		} else {
			result = server.groupDelayTest(ctx, outboundGroup, url, groupDelayNodeTimeout)
		}

		if err != nil {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		render.JSON(w, r, result)
	}
}

// One outbound the sweep will dial, together with every member tag of the group
// that resolves to it.
type groupDelayMember struct {
	outbound adapter.Outbound
	realTag  string
	tags     []string
	testedAt time.Time
}

// groupDelayMembers orders a sweep: the member in use first, then those not measured within
// groupDelayFreshWindow in group order, then the recently measured, oldest first. Members
// resolving to one outbound share a test. A failed test counts as a measurement.
func (s *Server) groupDelayMembers(outboundGroup adapter.OutboundGroup) []groupDelayMember {
	var members []groupDelayMember
	indexByRealTag := make(map[string]int)
	for _, tag := range outboundGroup.All() {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			continue
		}
		realTag := group.RealTag(s.outbound, detour)
		if index, loaded := indexByRealTag[realTag]; loaded {
			members[index].tags = append(members[index].tags, tag)
			continue
		}
		realOutbound := detour
		if realTag != tag {
			realOutbound, loaded = s.outbound.Outbound(realTag)
			if !loaded {
				continue
			}
		}
		testedAt := s.groupDelayTestedAt(realTag)
		if history := s.urlTestHistory.LoadURLTestHistory(realTag); history != nil && history.Time.After(testedAt) {
			testedAt = history.Time
		}
		indexByRealTag[realTag] = len(members)
		members = append(members, groupDelayMember{
			outbound: realOutbound,
			realTag:  realTag,
			tags:     []string{tag},
			testedAt: testedAt,
		})
	}
	selected := outboundGroup.Now()
	isSelected := func(member groupDelayMember) bool {
		return member.realTag == selected || slices.Contains(member.tags, selected)
	}
	staleBefore := time.Now().Add(-groupDelayFreshWindow)
	sort.SliceStable(members, func(i, j int) bool {
		if isSelected(members[i]) != isSelected(members[j]) {
			return isSelected(members[i])
		}
		leftFresh := members[i].testedAt.After(staleBefore)
		rightFresh := members[j].testedAt.After(staleBefore)
		if leftFresh != rightFresh {
			return rightFresh
		}
		if !leftFresh {
			return false
		}
		return members[i].testedAt.Before(members[j].testedAt)
	})
	return members
}

func (s *Server) groupDelayTestedAt(tag string) time.Time {
	s.groupDelayAccess.Lock()
	defer s.groupDelayAccess.Unlock()
	return s.groupDelayAttempts[tag]
}

func (s *Server) groupDelayTested(tag string) {
	s.groupDelayAccess.Lock()
	defer s.groupDelayAccess.Unlock()
	if s.groupDelayAttempts == nil {
		s.groupDelayAttempts = make(map[string]time.Time)
	}
	s.groupDelayAttempts[tag] = time.Now()
}

// Tests every member of a group that does not test itself, and answers with the
// delays measured before the request's deadline.
func (s *Server) groupDelayTest(ctx context.Context, outboundGroup adapter.OutboundGroup, link string, nodeTimeout time.Duration) map[string]uint16 {
	result := make(map[string]uint16)
	var resultAccess sync.Mutex
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](groupDelayConcurrency))
	for _, member := range s.groupDelayMembers(outboundGroup) {
		b.Go(member.realTag, func() (any, error) {
			if ctx.Err() != nil {
				return nil, nil
			}
			testCtx, cancel := context.WithTimeout(ctx, nodeTimeout)
			defer cancel()
			delay, err := urltest.URLTest(testCtx, link, member.outbound)
			s.groupDelayTested(member.realTag)
			if err != nil {
				// Running out of the sweep's time says nothing about the member,
				// so its last delay stays.
				if ctx.Err() != nil {
					return nil, nil
				}
				s.logger.Debug("outbound ", member.realTag, " unavailable: ", err)
				s.urlTestHistory.DeleteURLTestHistory(member.realTag)
				return nil, nil
			}
			s.logger.Debug("outbound ", member.realTag, " available: ", delay, "ms")
			s.urlTestHistory.StoreURLTestHistory(member.realTag, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: delay,
			})
			resultAccess.Lock()
			for _, tag := range member.tags {
				result[tag] = delay
			}
			resultAccess.Unlock()
			return nil, nil
		})
	}
	// A dial may ignore cancellation, so the answer does not wait for the batch
	// past the deadline; late results still reach the history.
	swept := make(chan struct{})
	go func() {
		b.Wait()
		close(swept)
	}()
	select {
	case <-swept:
	case <-ctx.Done():
	}

	resultAccess.Lock()
	defer resultAccess.Unlock()
	return maps.Clone(result)
}
