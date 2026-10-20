package urltest

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

const (
	coordinatorPruneInterval = time.Minute
	coordinatorRetention     = 30 * time.Minute
)

// Coordinator collapses concurrent URL tests of the same outbound and lets
// independent groups reuse a recent result instead of probing the same node
// once per group and per interval.
type Coordinator struct {
	access    sync.Mutex
	checks    map[coordinatorKey]*coordinatorCheck
	lastPrune time.Time
}

// coordinatorKey identifies a question about an outbound. The timeout is part
// of it because groups probe the same node with different budgets, and a
// verdict produced under one budget does not answer for another.
type coordinatorKey struct {
	tag            string
	link           string
	expectedStatus string
	timeout        time.Duration
}

type coordinatorCheck struct {
	done      chan struct{}
	at        time.Time
	delay     uint16
	err       error
	abandoned bool
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		checks:    make(map[coordinatorKey]*coordinatorCheck),
		lastPrune: time.Now(),
	}
}

// Check runs a URL test for tag with the given timeout, unless an identical
// test is already running or finished less than maxAge ago; pass maxAge 0 to
// force a fresh test. It returns the delay and the time the returned result was
// produced, so callers can store an accurate history record.
func (c *Coordinator) Check(ctx context.Context, link string, expectedStatus ExpectedStatus, tag string, detour N.Dialer, timeout time.Duration, maxAge time.Duration) (uint16, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return 0, time.Now(), err
	}
	key := coordinatorKey{tag: tag, link: link, expectedStatus: expectedStatusKey(expectedStatus), timeout: timeout}
	c.access.Lock()
	for {
		existing, loaded := c.checks[key]
		if !loaded {
			break
		}
		select {
		case <-existing.done:
			if maxAge > 0 && !existing.abandoned && time.Since(existing.at) < maxAge {
				c.access.Unlock()
				return existing.delay, existing.at, existing.err
			}
		default:
			c.access.Unlock()
			select {
			case <-existing.done:
				if !existing.abandoned {
					return existing.delay, existing.at, existing.err
				}
			case <-ctx.Done():
				return 0, time.Now(), ctx.Err()
			}
			c.access.Lock()
			continue
		}
		break
	}
	check := &coordinatorCheck{done: make(chan struct{})}
	c.checks[key] = check
	c.pruneLocked()
	c.access.Unlock()

	testCtx, cancel := context.WithTimeout(ctx, timeout)
	testDone := make(chan struct{})
	var (
		delay   uint16
		testErr error
	)
	go func() {
		delay, testErr = URLTestWithExpectedStatus(testCtx, link, detour, expectedStatus)
		close(testDone)
	}()
	select {
	case <-testDone:
		check.delay, check.err = delay, testErr
	case <-testCtx.Done():
		check.err = testCtx.Err()
	}
	cancel()
	check.at = time.Now()
	// A caller that walked away says nothing about the node.
	check.abandoned = ctx.Err() != nil
	close(check.done)
	if check.abandoned {
		c.access.Lock()
		if c.checks[key] == check {
			delete(c.checks, key)
		}
		c.access.Unlock()
	}
	return check.delay, check.at, check.err
}

func (c *Coordinator) pruneLocked() {
	now := time.Now()
	if now.Sub(c.lastPrune) < coordinatorPruneInterval {
		return
	}
	c.lastPrune = now
	for key, check := range c.checks {
		select {
		case <-check.done:
			if now.Sub(check.at) > coordinatorRetention {
				delete(c.checks, key)
			}
		default:
		}
	}
}

func expectedStatusKey(status ExpectedStatus) string {
	if len(status) == 0 {
		return ""
	}
	var builder strings.Builder
	for index, item := range status {
		if index > 0 {
			builder.WriteByte('/')
		}
		builder.WriteString(strconv.Itoa(int(item.Start)))
		builder.WriteByte('-')
		builder.WriteString(strconv.Itoa(int(item.End)))
	}
	return builder.String()
}
