package clashapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// A group that does not test itself, which is what every Forkop section is: a
// Selector answers the delay endpoint through the sweep in the handler.
type groupDelayTestGroup struct {
	*linkAPIOutbound
	all []string
	now string
}

func (g *groupDelayTestGroup) Now() string   { return g.now }
func (g *groupDelayTestGroup) All() []string { return g.all }

// A member whose dial does whatever the test needs: answer, refuse at once, or
// hang until its deadline runs out.
type groupDelayTestOutbound struct {
	*linkAPIOutbound
	dial  func(ctx context.Context) (net.Conn, error)
	calls atomic.Int32
	held  atomic.Int64
}

func (o *groupDelayTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.calls.Add(1)
	return o.dial(ctx)
}

func (o *groupDelayTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

func newGroupDelayAdapter(tag string) *linkAPIOutbound {
	return &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil)}
}

// Reachable but never answers: it holds a sweep slot for as long as it is allowed to.
func newGroupDelayHangingOutbound(tag string) *groupDelayTestOutbound {
	outbound := &groupDelayTestOutbound{linkAPIOutbound: newGroupDelayAdapter(tag)}
	outbound.dial = func(ctx context.Context) (net.Conn, error) {
		startedAt := time.Now()
		<-ctx.Done()
		outbound.held.Store(int64(time.Since(startedAt)))
		return nil, ctx.Err()
	}
	return outbound
}

func newGroupDelayRefusingOutbound(tag string) *groupDelayTestOutbound {
	outbound := &groupDelayTestOutbound{linkAPIOutbound: newGroupDelayAdapter(tag)}
	outbound.dial = func(context.Context) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	return outbound
}

func newGroupDelayAnsweringOutbound(tag string, address string) *groupDelayTestOutbound {
	outbound := &groupDelayTestOutbound{linkAPIOutbound: newGroupDelayAdapter(tag)}
	outbound.dial = func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", address)
	}
	return outbound
}

func newGroupDelayTestServer(t *testing.T, outbounds ...adapter.Outbound) *Server {
	t.Helper()
	clashServer, err := NewServer(clashTestContext(context.Background()), log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = &linkAPIOutboundManager{outbounds: outbounds}
	return server
}

func serveGroupDelay(server *Server, groupTag string, timeout int) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodGet,
		"/group/"+url.PathEscape(groupTag)+"/delay?url=https%3A%2F%2Fexample.com&timeout="+strconv.Itoa(timeout),
		nil,
	)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

// Members a sweep never reached keep their stored delay.
func TestGroupDelayKeepsHistoryOfMembersItCouldNotReach(t *testing.T) {
	const groupTag = "proxy"
	memberTags := make([]string, 0, 12)
	outbounds := make([]adapter.Outbound, 0, 13)
	for index := range 12 {
		tag := fmt.Sprintf("proxy/node %d", index)
		memberTags = append(memberTags, tag)
		outbounds = append(outbounds, newGroupDelayHangingOutbound(tag))
	}
	outbounds = append(outbounds, &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             memberTags,
	})
	server := newGroupDelayTestServer(t, outbounds...)
	for _, tag := range memberTags {
		server.urlTestHistory.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 42})
	}

	response := serveGroupDelay(server, groupTag, 200)
	if response.Code != http.StatusOK {
		t.Fatalf("group delay returned %d: %s", response.Code, response.Body)
	}
	for _, tag := range memberTags {
		if server.urlTestHistory.LoadURLTestHistory(tag) == nil {
			t.Fatalf("group delay forgot %q, a member whose test it never finished", tag)
		}
	}
}

// A member that failed its own test is forgotten: a stored delay means the node answered.
func TestGroupDelayForgetsMembersThatFailedTheirOwnTest(t *testing.T) {
	const (
		groupTag  = "proxy"
		memberTag = "proxy/dead"
	)
	member := newGroupDelayRefusingOutbound(memberTag)
	server := newGroupDelayTestServer(t, member, &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{memberTag},
	})
	server.urlTestHistory.StoreURLTestHistory(memberTag, &adapter.URLTestHistory{Time: time.Now(), Delay: 42})

	response := serveGroupDelay(server, groupTag, 2000)
	if response.Code != http.StatusOK {
		t.Fatalf("group delay returned %d: %s", response.Code, response.Body)
	}
	if server.urlTestHistory.LoadURLTestHistory(memberTag) != nil {
		t.Fatal("group delay kept the delay of a member that refused the connection")
	}
}

// A hanging member must not keep its slot for the whole request.
func TestGroupDelayGivesEachMemberItsOwnDeadline(t *testing.T) {
	const groupTag = "proxy"
	members := []*groupDelayTestOutbound{
		newGroupDelayHangingOutbound("proxy/node 1"),
		newGroupDelayHangingOutbound("proxy/node 2"),
		newGroupDelayHangingOutbound("proxy/node 3"),
	}
	outbounds := make([]adapter.Outbound, 0, len(members)+1)
	memberTags := make([]string, 0, len(members))
	for _, member := range members {
		outbounds = append(outbounds, member)
		memberTags = append(memberTags, member.Tag())
	}
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             memberTags,
	}
	outbounds = append(outbounds, outboundGroup)
	server := newGroupDelayTestServer(t, outbounds...)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startedAt := time.Now()
	server.groupDelayTest(ctx, outboundGroup, "https://example.com", 150*time.Millisecond)
	swept := time.Since(startedAt)

	if swept > time.Second {
		t.Fatalf("sweep of three hanging members took %s, so they held their slots", swept)
	}
	for _, member := range members {
		held := time.Duration(member.held.Load())
		if held > time.Second {
			t.Fatalf("%q held its slot for %s", member.Tag(), held)
		}
	}
}

// A second press continues through the group: what the first measured goes behind what it never
// reached.
func TestGroupDelaySweepContinuesWhereTheLastPressStopped(t *testing.T) {
	const groupTag = "proxy"
	const (
		firstTag    = "proxy/measured first"
		untestedTag = "proxy/untested"
		lastTag     = "proxy/measured last"
	)
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{firstTag, untestedTag, lastTag},
	}
	server := newGroupDelayTestServer(t,
		newGroupDelayRefusingOutbound(firstTag),
		newGroupDelayRefusingOutbound(untestedTag),
		newGroupDelayRefusingOutbound(lastTag),
		outboundGroup,
	)
	now := time.Now()
	server.groupDelayAttempts = map[string]time.Time{
		firstTag: now.Add(-3 * time.Second),
		lastTag:  now.Add(-1 * time.Second),
	}

	var order []string
	for _, member := range server.groupDelayMembers(outboundGroup) {
		order = append(order, member.realTag)
	}
	expected := []string{untestedTag, firstTag, lastTag}
	if !slices.Equal(order, expected) {
		t.Fatalf("sweep order %v, expected %v", order, expected)
	}
}

// Members resolving to the same outbound, such as a nested group, all get the result.
func TestGroupDelayAnswersEveryMemberSharingOneOutbound(t *testing.T) {
	const (
		groupTag  = "proxy"
		nodeTag   = "proxy/node"
		nestedTag = "proxy/nested"
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	node := newGroupDelayAnsweringOutbound(nodeTag, target.Listener.Addr().String())
	nested := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(nestedTag),
		all:             []string{nodeTag},
		now:             nodeTag,
	}
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{nestedTag, nodeTag},
	}
	server := newGroupDelayTestServer(t, node, nested, outboundGroup)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := server.groupDelayTest(ctx, outboundGroup, target.URL, groupDelayNodeTimeout)

	nodeDelay, nodeAnswered := result[nodeTag]
	nestedDelay, nestedAnswered := result[nestedTag]
	if !nodeAnswered || !nestedAnswered {
		t.Fatalf("group delay answered %v, expected both %q and %q", result, nodeTag, nestedTag)
	}
	if nodeDelay != nestedDelay {
		t.Fatalf("one outbound reported two delays: %d and %d", nodeDelay, nestedDelay)
	}
	if calls := node.calls.Load(); calls != 1 {
		t.Fatalf("the shared outbound was dialed %d times", calls)
	}
	if server.urlTestHistory.LoadURLTestHistory(nodeTag) == nil {
		t.Fatal("a member that answered was left without a delay")
	}
}

// Members still queued when the deadline passes are not tested: a dial cancelled before it starts
// still costs most of a second.
func TestGroupDelayStopsStartingTestsAfterItsDeadline(t *testing.T) {
	const groupTag = "proxy"
	const slowDial = 300 * time.Millisecond
	memberTags := make([]string, 0, 40)
	outbounds := make([]adapter.Outbound, 0, 41)
	for index := range 40 {
		tag := fmt.Sprintf("proxy/node %d", index)
		outbound := &groupDelayTestOutbound{linkAPIOutbound: newGroupDelayAdapter(tag)}
		// A dial that ignores its context, like a resolver that has already
		// committed to a query by the time the sweep is cancelled.
		outbound.dial = func(context.Context) (net.Conn, error) {
			time.Sleep(slowDial)
			return nil, errors.New("unavailable")
		}
		memberTags = append(memberTags, tag)
		outbounds = append(outbounds, outbound)
	}
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             memberTags,
	}
	outbounds = append(outbounds, outboundGroup)
	server := newGroupDelayTestServer(t, outbounds...)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	server.groupDelayTest(ctx, outboundGroup, "https://example.com", groupDelayNodeTimeout)
	swept := time.Since(startedAt)

	// The first slot of members is already dialing when the deadline passes; the
	// three behind them would double, treble and quadruple that if they ran.
	if swept > 2*slowDial {
		t.Fatalf("sweep answered %s after a deadline of 100ms", swept)
	}
}

// A dial that ignores its cancelled deadline must not extend the request's timeout.
func TestGroupDelayAnswersOnTimeEvenIfAMemberDialOverrunsIt(t *testing.T) {
	const groupTag = "proxy"
	const memberTag = "proxy/stuck"
	const budget = 200 * time.Millisecond
	member := &groupDelayTestOutbound{linkAPIOutbound: newGroupDelayAdapter(memberTag)}
	member.dial = func(context.Context) (net.Conn, error) {
		time.Sleep(2 * time.Second)
		return nil, errors.New("unavailable")
	}
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{memberTag},
	}
	server := newGroupDelayTestServer(t, member, outboundGroup)

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	startedAt := time.Now()
	server.groupDelayTest(ctx, outboundGroup, "https://example.com", groupDelayNodeTimeout)
	swept := time.Since(startedAt)

	if swept > budget*4 {
		t.Fatalf("sweep answered %s after a budget of %s", swept, budget)
	}
}

// A failed member keeps no delay, so the order must not take it for one never tested and dial
// every dead node first.
func TestGroupDelaySweepDoesNotRepeatMembersThatJustFailed(t *testing.T) {
	const groupTag = "proxy"
	const (
		failedTag   = "proxy/failed"
		untestedTag = "proxy/untested"
		answeredTag = "proxy/answered"
	)
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		// The failed member comes first in the group, so an order that ignores
		// it leaves it first here too.
		all: []string{failedTag, untestedTag, answeredTag},
	}
	server := newGroupDelayTestServer(t,
		newGroupDelayRefusingOutbound(failedTag),
		newGroupDelayRefusingOutbound(untestedTag),
		newGroupDelayRefusingOutbound(answeredTag),
		outboundGroup,
	)
	now := time.Now()
	// Tested by the press just before this one and failed: no delay was kept
	// for it, and it must not be dialed again ahead of everything else.
	server.groupDelayAttempts = map[string]time.Time{failedTag: now.Add(-2 * time.Second)}
	// Answered an hour ago, so it is the stalest thing actually worth retesting.
	server.urlTestHistory.StoreURLTestHistory(answeredTag, &adapter.URLTestHistory{
		Time:  now.Add(-time.Hour),
		Delay: 42,
	})

	var order []string
	for _, member := range server.groupDelayMembers(outboundGroup) {
		order = append(order, member.realTag)
	}
	expected := []string{untestedTag, answeredTag, failedTag}
	if !slices.Equal(order, expected) {
		t.Fatalf("sweep order %v, expected %v", order, expected)
	}
}

// The member in use is what the group's own row shows, so a press refreshes it first.
func TestGroupDelaySweepsTheMemberInUseFirst(t *testing.T) {
	const groupTag = "proxy"
	const (
		staleTag    = "proxy/stale"
		selectedTag = "proxy/selected"
	)
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{staleTag, selectedTag},
		now:             selectedTag,
	}
	server := newGroupDelayTestServer(t,
		newGroupDelayRefusingOutbound(staleTag),
		newGroupDelayRefusingOutbound(selectedTag),
		outboundGroup,
	)
	now := time.Now()
	// The one in use was just measured; the other has not been tested for an
	// hour, so staleness alone would put it first.
	server.groupDelayAttempts = map[string]time.Time{
		selectedTag: now,
		staleTag:    now.Add(-time.Hour),
	}

	var order []string
	for _, member := range server.groupDelayMembers(outboundGroup) {
		order = append(order, member.realTag)
	}
	expected := []string{selectedTag, staleTag}
	if !slices.Equal(order, expected) {
		t.Fatalf("sweep order %v, expected %v", order, expected)
	}
}

// A press that does not continue the last one starts at the top of the group, its owner's order
// of priority.
func TestGroupDelaySweepReturnsToTheGroupOrderAfterAPause(t *testing.T) {
	const groupTag = "proxy"
	const (
		personalTag = "proxy/personal"
		neverTag    = "proxy/never tested"
		heapTag     = "proxy/heap"
	)
	outboundGroup := &groupDelayTestGroup{
		linkAPIOutbound: newGroupDelayAdapter(groupTag),
		all:             []string{personalTag, neverTag, heapTag},
	}
	server := newGroupDelayTestServer(t,
		newGroupDelayRefusingOutbound(personalTag),
		newGroupDelayRefusingOutbound(neverTag),
		newGroupDelayRefusingOutbound(heapTag),
		outboundGroup,
	)
	now := time.Now()
	// Long enough ago that none of this belongs to a press still in progress.
	server.groupDelayAttempts = map[string]time.Time{
		personalTag: now.Add(-10 * time.Minute),
		heapTag:     now.Add(-5 * time.Minute),
	}

	var order []string
	for _, member := range server.groupDelayMembers(outboundGroup) {
		order = append(order, member.realTag)
	}
	expected := []string{personalTag, neverTag, heapTag}
	if !slices.Equal(order, expected) {
		t.Fatalf("sweep order %v, expected %v", order, expected)
	}
}
