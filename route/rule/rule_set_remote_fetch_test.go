package rule

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

const testSourceSet = `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`

func newFetchTestRuleSet(url string) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(context.Background())
	return &RemoteRuleSet{
		ctx:        ctx,
		cancel:     cancel,
		logger:     log.NewNOPFactory().NewLogger("test"),
		tag:        "test",
		url:        url,
		httpClient: &http.Client{},
		options:    optionsWithFormat(C.RuleSetFormatSource),
	}
}

func swapTimeouts(stall, startDeadline time.Duration) func() {
	oldStall, oldStart := ruleSetStallTimeout, ruleSetStartDeadline
	ruleSetStallTimeout, ruleSetStartDeadline = stall, startDeadline
	return func() { ruleSetStallTimeout, ruleSetStartDeadline = oldStall, oldStart }
}

func swapMaxSize(size int) func() {
	old := ruleSetMaxSize
	ruleSetMaxSize = size
	return func() { ruleSetMaxSize = old }
}

// A download that sends its headers and then goes silent must not hold the caller: the stall
// timer ends it. At start this is the difference between the LAN getting DNS after a bounded
// wait and having no DNS until the TCP connection dies.
func TestRemoteRuleSetFetchStalls(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	}))
	defer server.Close()
	defer close(release)

	defer swapTimeouts(50*time.Millisecond, time.Hour)()
	set := newFetchTestRuleSet(server.URL)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := set.fetch(context.Background(), false)
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "no data for")
		require.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not return after the stall timeout")
	}
}

// A slow but steady download, whose total time far exceeds the stall timeout, must still
// succeed: a big list on a slow router link is exactly this case.
func TestRemoteRuleSetFetchSlowButSteady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for i := 0; i < 20; i++ {
			io.WriteString(w, "a"+strconv.Itoa(i)+".example.com\n")
			flusher.Flush()
			time.Sleep(40 * time.Millisecond)
		}
	}))
	defer server.Close()

	defer swapTimeouts(200*time.Millisecond, 200*time.Millisecond)()
	set := newFetchTestRuleSet(server.URL)
	set.options = optionsWithFormat(C.RuleSetFormatText)
	loaded, err := set.fetch(context.Background(), false)
	require.NoError(t, err)
	require.True(t, loaded)
}

// A body larger than any real rule-set is refused instead of being read into memory without
// bound.
func TestRemoteRuleSetFetchSizeCap(t *testing.T) {
	defer swapMaxSize(1 << 20)()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		chunk := strings.Repeat("A", 1<<20)
		for range 3 {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()

	_, err := newFetchTestRuleSet(server.URL).fetch(context.Background(), false)
	require.ErrorContains(t, err, "larger than 1 MB")
}

// A response that declares more than the cap is refused by its length: nothing of the body
// is read into memory.
func TestRemoteRuleSetDeclaredTooLarge(t *testing.T) {
	defer swapMaxSize(1 << 20)()
	// far more than the socket buffers of both ends take in: a server whose answer is
	// not read cannot have written all of it
	const declared = 64 << 20
	var sent int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("A", 64<<10))
		for sent < declared {
			n, err := w.Write(chunk)
			sent += n
			if err != nil {
				return
			}
		}
	}))
	_, err := newFetchTestRuleSet(server.URL).fetch(context.Background(), false)
	require.ErrorContains(t, err, "larger than 1 MB")
	server.Close()
	require.Less(t, sent, declared, "the client must stop the transfer instead of reading it")
}

// A page served with status 200 where a binary rule-set is expected is refused by its first
// bytes, and the error says what came: size, type and the first bytes, quoted.
func TestRemoteRuleSetNotBinary(t *testing.T) {
	page := "<!DOCTYPE html>\n<html><body>blocked\x1b[31m</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	}))
	defer server.Close()
	set := newFetchTestRuleSet(server.URL)
	set.options = optionsWithFormat(C.RuleSetFormatBinary)
	_, err := set.fetch(context.Background(), false)
	require.Error(t, err)
	message := err.Error()
	require.Contains(t, message, "not a binary rule-set")
	require.Contains(t, message, strconv.Itoa(len(page))+" bytes")
	require.Contains(t, message, `Content-Type "text/html; charset=utf-8"`)
	require.Contains(t, message, `starts with "<!DOCTYPE html>\n"`)
	require.NotContains(t, message, "\n", "the server's bytes must not break the log line")
}

// A source rule-set that does not parse reports the same description.
func TestRemoteRuleSetSourceParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>not a list</html>")
	}))
	defer server.Close()
	_, err := newFetchTestRuleSet(server.URL).fetch(context.Background(), false)
	require.ErrorContains(t, err, `read rule-set (23 bytes, Content-Type "text/html", starts with "<html>not a list")`)
}

// A list loads with a declared length and without one (chunked).
func TestRemoteRuleSetBodyLoads(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if chunked {
				w.(http.Flusher).Flush()
			}
			io.WriteString(w, testSourceSet)
		}))
		set := newFetchTestRuleSet(server.URL)
		loaded, err := set.fetch(context.Background(), false)
		require.NoError(t, err, "chunked=%v", chunked)
		require.True(t, loaded)
		require.Len(t, set.rules, 1)
		server.Close()
	}
}

// The download is dialed as an external connection, so that a group switching members does
// not close it together with its own connections.
func TestRemoteRuleSetFetchIsExternalConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	var external bool
	set := newFetchTestRuleSet(server.URL)
	set.httpClient = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			external = interrupt.IsExternalConnectionFromContext(ctx)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	_, err := set.fetch(context.Background(), false)
	require.NoError(t, err)
	require.True(t, external)
}

// A rule-set closed while its list comes in neither parses nor keeps it: a box replaced by a
// reload must not parse lists beside the downloads of the new one.
func TestRemoteRuleSetClosedDuringDownload(t *testing.T) {
	sending := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(testSourceSet)))
		io.WriteString(w, testSourceSet[:10])
		w.(http.Flusher).Flush()
		close(sending)
		<-release
		io.WriteString(w, testSourceSet[10:])
	}))
	defer server.Close()
	set := newFetchTestRuleSet(server.URL)
	done := make(chan error, 1)
	go func() {
		_, err := set.fetch(context.Background(), false)
		done <- err
	}()
	<-sending
	set.cancel()
	close(release)
	require.ErrorIs(t, <-done, context.Canceled)
	require.Zero(t, set.revision)
	require.Empty(t, set.rules)
}

type levelLog struct {
	access sync.Mutex
	lines  []string
}

func (l *levelLog) WriteMessage(level log.Level, message string) {
	l.access.Lock()
	defer l.access.Unlock()
	name := map[log.Level]string{log.LevelError: "ERROR", log.LevelInfo: "INFO", log.LevelDebug: "DEBUG"}[level]
	l.lines = append(l.lines, name+" "+message)
}

func (l *levelLog) take() []string {
	l.access.Lock()
	defer l.access.Unlock()
	lines := l.lines
	l.lines = nil
	return lines
}

func countPrefix(lines []string, prefix string) int {
	var count int
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

func newLevelLogger(t *testing.T, writer *levelLog) log.ContextLogger {
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
	factory.SetLevel(log.LevelDebug)
	require.NoError(t, factory.Start())
	t.Cleanup(func() { factory.Close() })
	return factory.NewLogger("rule-set")
}

// A rule-set that keeps failing to update logs the first failure as an error, the next ones
// at debug and, every ruleSetFailureLogInterval, a count; the success after them says how
// many there were. Only an update that loaded a list reports it, a failed or not-modified
// one does not.
func TestRemoteRuleSetUpdateFailuresLogged(t *testing.T) {
	var mode atomic.Value
	mode.Store("fail")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load().(string) {
		case "fail":
			w.WriteHeader(http.StatusBadGateway)
		case "list":
			w.Header().Set("Etag", `"v1"`)
			io.WriteString(w, testSourceSet)
		case "same":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()

	writer := &levelLog{}
	set := newFetchTestRuleSet(server.URL)
	set.logger = newLevelLogger(t, writer)
	for range 3 {
		require.False(t, set.updateOnce())
	}
	lines := writer.take()
	require.Len(t, lines, 6) // each attempt also logs "updating rule-set" at debug
	require.Equal(t, 1, countPrefix(lines, "ERROR"))
	require.Equal(t, 5, countPrefix(lines, "DEBUG"))

	set.failureLogged = time.Now().Add(-ruleSetFailureLogInterval)
	require.False(t, set.updateOnce())
	lines = writer.take()
	require.Equal(t, 1, countPrefix(lines, "ERROR"))
	require.Contains(t, strings.Join(lines, "\n"), "4 failed attempts")

	mode.Store("list")
	require.True(t, set.updateOnce())
	require.Contains(t, strings.Join(writer.take(), "\n"), "succeeded after 4 failed attempts")
	require.Zero(t, set.failures)

	mode.Store("same")
	require.False(t, set.updateOnce())
	require.Zero(t, countPrefix(writer.take(), "ERROR"))
}

// An update cut by the shutdown is not a failed update: no error line, no failure counted.
func TestRemoteRuleSetUpdateCancelledByShutdown(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-release
	}))
	defer server.Close()
	defer close(release)

	writer := &levelLog{}
	set := newFetchTestRuleSet(server.URL)
	set.logger = newLevelLogger(t, writer)
	time.AfterFunc(200*time.Millisecond, set.cancel)
	require.False(t, set.updateOnce())
	require.Zero(t, set.failures)
	require.Zero(t, countPrefix(writer.take(), "ERROR"))
}

// A rule-set whose download failed at the start is retried within seconds, not after its
// update_interval, and is on the regular schedule once it came.
func TestRuleSetUpdaterRetriesASetThatStartedEmpty(t *testing.T) {
	defer func(saved []time.Duration) { ruleSetRetryDelays = saved }(ruleSetRetryDelays)
	ruleSetRetryDelays = []time.Duration{20 * time.Millisecond}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()

	set := newFetchTestRuleSet(server.URL)
	set.updateInterval = time.Hour
	_, err := set.fetch(context.Background(), true)
	require.Error(t, err)
	set.startedEmpty = true
	updater := NewRuleSetUpdater(set.ctx, []adapter.RuleSet{set})
	updater.Start()
	defer updater.Close()
	require.Eventually(t, func() bool { return !set.updatedAt().IsZero() }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, 4, requests.Load(), "a set that came was fetched again before its update_interval")
}

// Rule-sets due together are downloaded together, ruleSetUpdateConcurrency at a time: six
// sets whose server answers after 300 ms take two rounds, not six.
func TestRuleSetUpdaterConcurrent(t *testing.T) {
	var inFlight, most atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sets := make([]adapter.RuleSet, 6)
	for index := range sets {
		set := newFetchTestRuleSet(server.URL)
		set.ctx = ctx
		set.updateInterval = time.Hour
		sets[index] = set
	}
	updater := NewRuleSetUpdater(ctx, sets)
	started := time.Now()
	updater.Start()
	defer updater.Close()
	require.Eventually(t, func() bool {
		for _, set := range sets {
			if set.(*RemoteRuleSet).updatedAt().IsZero() {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
	require.EqualValues(t, ruleSetUpdateConcurrency, most.Load())
	require.Less(t, time.Since(started), 1500*time.Millisecond, "the sets were downloaded one by one")
}

// What a server sends reaches the log as one printable line of a bounded length.
func TestRuleSetLogText(t *testing.T) {
	t.Parallel()
	require.Equal(t, "unexpected status: 404 Not?Found??[31m", logText(E.New("unexpected status: 404 Not\nFound\r\x1b[31m")))
	require.Equal(t, "rules[0]: unknown rule type: x?y", logText(E.New("rules[0]: unknown rule type: x\x00y")))
	long := logText(E.New(strings.Repeat("я", 600)))
	require.LessOrEqual(t, len(long), 515)
	require.True(t, strings.HasSuffix(long, "..."))
	require.True(t, utf8.ValidString(long))
	require.NotContains(t, long, "?")
}

func optionsWithFormat(format string) option.RuleSet {
	return option.RuleSet{Type: C.RuleSetTypeRemote, Tag: []string{"test"}, Format: format}
}
