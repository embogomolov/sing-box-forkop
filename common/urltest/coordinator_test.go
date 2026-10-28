package urltest

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type coordinatorTestDialer struct {
	access sync.Mutex
	dials  int
	block  chan struct{}
}

func (d *coordinatorTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials++
	block := d.block
	d.access.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}()
	return client, nil
}

func (d *coordinatorTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (d *coordinatorTestDialer) dialCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials
}

func TestCoordinatorReusesFreshResults(t *testing.T) {
	coordinator := NewCoordinator()
	dialer := &coordinatorTestDialer{}
	link := "http://health.test/generate_204"
	if _, _, err := coordinator.Check(context.Background(), link, nil, "node", dialer, time.Second, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.Check(context.Background(), link, nil, "node", dialer, time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if dialer.dialCount() != 1 {
		t.Fatalf("a fresh result was not reused: %d", dialer.dialCount())
	}
	if _, _, err := coordinator.Check(context.Background(), link, nil, "node", dialer, time.Second, 0); err != nil {
		t.Fatal(err)
	}
	if dialer.dialCount() != 2 {
		t.Fatalf("a forced check reused a cached result: %d", dialer.dialCount())
	}
	if _, _, err := coordinator.Check(context.Background(), link, nil, "other", dialer, time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if dialer.dialCount() != 3 {
		t.Fatalf("results are shared between different outbounds: %d", dialer.dialCount())
	}
}

func TestCoordinatorMultipleURLs(t *testing.T) {
	coordinator := NewCoordinator()
	dialer := &coordinatorTestDialer{}
	links := []string{"http://first.test", "http://second.test"}
	oldest := time.Now().Add(-time.Second)
	for i, link := range links {
		done := make(chan struct{})
		close(done)
		coordinator.checks[coordinatorKey{tag: "node", link: link, timeout: time.Second}] = &coordinatorCheck{
			done: done, at: oldest.Add(time.Duration(i) * time.Millisecond), delay: uint16(10 + 70*i),
		}
	}
	delay, at, err := coordinator.CheckURLs(context.Background(), links, nil, "node", dialer, time.Second, time.Minute)
	if err != nil || delay != 80 || !at.Equal(oldest) || dialer.dialCount() != 0 {
		t.Fatalf("unexpected aggregate: delay=%d at=%v error=%v dials=%d", delay, at, err, dialer.dialCount())
	}
	coordinator.checks[coordinatorKey{tag: "node", link: links[1], timeout: time.Second}].err = errors.New("unreachable")
	if _, _, err = coordinator.CheckURLs(context.Background(), links, nil, "node", dialer, time.Second, time.Minute); err == nil {
		t.Fatal("a failed second URL was accepted")
	}
}

func TestCoordinatorCollapsesConcurrentChecks(t *testing.T) {
	coordinator := NewCoordinator()
	dialer := &coordinatorTestDialer{block: make(chan struct{})}
	link := "http://health.test/generate_204"
	var wait sync.WaitGroup
	check := func() {
		defer wait.Done()
		_, _, _ = coordinator.Check(context.Background(), link, nil, "node", dialer, time.Second, 0)
	}
	wait.Add(1)
	go check()
	deadline := time.Now().Add(time.Second)
	for dialer.dialCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for index := 0; index < 3; index++ {
		wait.Add(1)
		go check()
	}
	time.Sleep(100 * time.Millisecond)
	close(dialer.block)
	wait.Wait()
	if dialer.dialCount() != 1 {
		t.Fatalf("concurrent checks were not collapsed: %d", dialer.dialCount())
	}
}

// Callers waiting on a check whose owner walked away share one new check.
func TestCoordinatorRestartsAnAbandonedCheckOnce(t *testing.T) {
	coordinator := NewCoordinator()
	dialer := &coordinatorTestDialer{block: make(chan struct{})}
	link := "http://health.test/generate_204"
	ownerContext, cancelOwner := context.WithCancel(context.Background())
	ownerDone := make(chan struct{})
	go func() {
		_, _, _ = coordinator.Check(ownerContext, link, nil, "node", dialer, time.Second, 0)
		close(ownerDone)
	}()
	deadline := time.Now().Add(time.Second)
	for dialer.dialCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var wait sync.WaitGroup
	for index := 0; index < 3; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, _, err := coordinator.Check(context.Background(), link, nil, "node", dialer, time.Second, 0); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	cancelOwner()
	<-ownerDone
	time.Sleep(100 * time.Millisecond)
	close(dialer.block)
	wait.Wait()
	if dialer.dialCount() != 2 {
		t.Fatalf("callers of an abandoned check did not share one new check: %d dials", dialer.dialCount())
	}
}

type coordinatorSlowDialer struct {
	access sync.Mutex
	dials  int
	delay  time.Duration
	fail   bool
}

func (d *coordinatorSlowDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials++
	delay := d.delay
	fail := d.fail
	d.access.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if fail {
		return nil, errors.New("unavailable")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}()
	return client, nil
}

func (d *coordinatorSlowDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (d *coordinatorSlowDialer) dialCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials
}

// Groups probe the same node with different budgets, so a result is only
// shared between callers that asked the same question.
func TestCoordinatorSharesResultsPerBudget(t *testing.T) {
	const link = "http://health.test/generate_204"

	check := func(coordinator *Coordinator, detour N.Dialer, budget time.Duration, maxAge time.Duration) error {
		_, _, err := coordinator.Check(context.Background(), link, nil, "node", detour, budget, maxAge)
		return err
	}

	quick := &coordinatorSlowDialer{}
	coordinator := NewCoordinator()
	if err := check(coordinator, quick, time.Second, 0); err != nil {
		t.Fatal(err)
	}
	if err := check(coordinator, quick, time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if quick.dialCount() != 1 {
		t.Fatalf("a recent result of the same check was not reused: %d", quick.dialCount())
	}
	if err := check(coordinator, quick, 20*time.Millisecond, time.Minute); err != nil {
		t.Fatal(err)
	}
	if quick.dialCount() != 2 {
		t.Fatalf("a different budget must run its own check: %d", quick.dialCount())
	}
	if err := check(coordinator, quick, time.Second, 0); err != nil {
		t.Fatal(err)
	}
	if quick.dialCount() != 3 {
		t.Fatalf("a forced check must not reuse a cached result: %d", quick.dialCount())
	}

	slow := &coordinatorSlowDialer{delay: 120 * time.Millisecond}
	coordinator = NewCoordinator()
	if err := check(coordinator, slow, 20*time.Millisecond, 0); err == nil {
		t.Fatal("a node slower than the budget must fail its check")
	}
	if err := check(coordinator, slow, 20*time.Millisecond, time.Minute); err == nil {
		t.Fatal("a node slower than the budget must fail its check")
	}
	if slow.dialCount() != 1 {
		t.Fatalf("a recent failure of the same check was not reused: %d", slow.dialCount())
	}
}
