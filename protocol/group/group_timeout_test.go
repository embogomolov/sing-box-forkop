package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type contextIgnoringOutbound struct {
	outboundAdapter.Adapter
	release chan struct{}
}

func (o *contextIgnoringOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	<-o.release
	return nil, errors.New("released")
}

func (o *contextIgnoringOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type slowCloseConn struct {
	net.Conn
	release chan struct{}
}

func (c *slowCloseConn) Close() error {
	<-c.release
	return c.Conn.Close()
}

func returnsWithin(t *testing.T, limit time.Duration, name string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		call()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v", name, limit)
	}
}

func TestURLTestGroupAnswersWhileADialIgnoresItsContext(t *testing.T) {
	node := &contextIgnoringOutbound{Adapter: outboundAdapter.NewAdapter("test", "node", []string{N.NetworkTCP}, nil), release: make(chan struct{})}
	defer close(node.release)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{node}, []string{"http://health.test/"}, nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	returnsWithin(t, time.Second, "a URLTest group test with a 100 ms budget", func() {
		_, _ = urlTestGroup.URLTest(ctx)
	})
}

func TestFallbackTestAnswersWhileABackgroundCheckRuns(t *testing.T) {
	slow := &fallbackBlockingOutbound{Adapter: outboundAdapter.NewAdapter("test", "slow", []string{N.NetworkTCP}, nil), started: make(chan struct{})}
	fallback := newTestFallback(fallbackCandidate{tag: slow.Tag(), outbound: slow})
	fallback.timeout = 3 * time.Second
	go fallback.checkOutbounds(context.Background(), 0)
	<-slow.started
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	returnsWithin(t, time.Second, "a Fallback test with a 100 ms budget", func() {
		_, _ = fallback.URLTest(ctx)
	})
}

func TestFallbackTestsGroupMembersWithoutSelectionOneByOne(t *testing.T) {
	dead := &fallbackHistoryGroupOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("urltest-a", false)}
	alive := &fallbackHistoryGroupOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("urltest-b", true)}
	fallback := newTestFallback(
		fallbackCandidate{tag: dead.Tag(), outbound: dead},
		fallbackCandidate{tag: alive.Tag(), outbound: alive, group: 1},
	)
	fallback.outbound = &testOutboundManager{outbounds: map[string]adapter.Outbound{dead.Tag(): dead, alive.Tag(): alive}}
	fallback.timeout = time.Second
	result, err := fallback.URLTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dead.dialCount != 1 || alive.dialCount != 1 {
		t.Fatalf("members without a selection were not tested one by one: dials %d and %d", dead.dialCount, alive.dialCount)
	}
	if fallback.health[dead.Tag()].alive || !fallback.health[alive.Tag()].alive || len(result) != 1 {
		t.Fatalf("members without a selection shared a verdict: %v", result)
	}
	if fallback.history.LoadURLTestHistory("") != nil {
		t.Fatal("history was stored under an empty tag")
	}
}

func TestFallbackSingleNodeTestDoesNotCheckTheGroup(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
	fallback.PerformUpdateCheck()
	select {
	case <-fallback.wake:
		t.Fatal("a single node test asked the fallback group for a health check")
	default:
	}
}

func TestURLTestGroupSelectsWhileAnInterruptClosesConnections(t *testing.T) {
	first := newTestOutbound("first")
	second := newTestOutbound("second")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{first.Tag(): first, second.Tag(): second}}
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{first, second}, nil, nil, 0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	urlTestGroup.storeHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	urlTestGroup.performUpdateCheck()
	client, server := net.Pipe()
	defer server.Close()
	release := make(chan struct{})
	urlTestGroup.interruptGroup.NewConn(&slowCloseConn{Conn: client, release: release}, false)
	urlTestGroup.storeHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		urlTestGroup.performUpdateCheck()
	}()
	defer func() {
		close(release)
		waitGroup.Wait()
	}()
	time.Sleep(50 * time.Millisecond)
	returnsWithin(t, 500*time.Millisecond, "selecting while old connections close", func() {
		_, _ = urlTestGroup.Select(N.NetworkTCP)
	})
}
