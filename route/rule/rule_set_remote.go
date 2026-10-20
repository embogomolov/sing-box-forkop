package rule

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	convertor "github.com/sagernet/sing-box/common/convertor/ruleset"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	tag            string
	url            string
	urlHash        [32]byte
	initialPath    string
	options        option.RuleSet
	updateInterval time.Duration
	httpClient     *http.Client
	updateAccess   sync.Mutex
	access         sync.RWMutex
	rules          []adapter.HeadlessRule
	metadata       adapter.RuleSetMetadata
	ipCIDRExport   adapter.RuleSetIPCIDRExport
	contentFormat  string
	revision       uint64
	lastUpdated    time.Time
	lastEtag       string
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	callbacks      list.List[adapter.RuleSetUpdateCallback]
	refs           atomic.Int32
	// the start had no list: the updater retries until the first download succeeds
	startedEmpty bool
	// the failed updates since the last success (see fetchFailed)
	failureAccess sync.Mutex
	failures      int
	failureLogged time.Time
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, tag string, options option.RuleSet) (*RemoteRuleSet, error) {
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	}
	var initialPath string
	if options.RemoteOptions.InitialPath != "" {
		initialPath = filemanager.BasePath(ctx, strings.ReplaceAll(options.RemoteOptions.InitialPath, C.RuleSetTagPlaceholder, tag))
		initialPath, _ = filepath.Abs(initialPath)
	}
	url := strings.ReplaceAll(options.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
	return &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		tag:            tag,
		url:            url,
		urlHash:        sha256.Sum256([]byte(url)),
		initialPath:    initialPath,
		options:        options,
		updateInterval: updateInterval,
		contentFormat:  options.Format,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *RemoteRuleSet) Name() string {
	return s.tag
}

func (s *RemoteRuleSet) String() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create rule-set http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.cacheFile != nil {
		savedSet := s.cacheFile.LoadRuleSet(s.tag)
		if savedSet != nil {
			if len(savedSet.URLHash) > 0 && !bytes.Equal(savedSet.URLHash, s.urlHash[:]) {
				s.logger.Info("cached rule-set was downloaded from another URL, will refetch")
			} else {
				err = s.loadBytes(savedSet.Content, savedSet.LastUpdated, savedSet.LastEtag)
				if err != nil {
					s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
				}
			}
		}
	}
	var loadedFromInitialPath bool
	if s.lastUpdated.IsZero() && s.initialPath != "" {
		var content []byte
		content, err = filemanager.ReadFile(s.ctx, s.initialPath)
		if err == nil {
			err = s.loadBytes(content, time.Time{}, "")
		}
		if err != nil {
			s.logger.Warn(E.Cause(err, "load initial rule-set from ", s.initialPath))
		} else {
			loadedFromInitialPath = true
		}
	}
	if s.lastUpdated.IsZero() && !loadedFromInitialPath {
		_, err = s.fetch(ctx, true)
		if err != nil {
			s.logger.Error("initial rule-set ", s.tag, " unavailable, continuing without it and retrying: ", logText(err))
			s.startedEmpty = true
		}
	}
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *RemoteRuleSet) ProviderSnapshot() adapter.RuleSetProviderSnapshot {
	s.access.RLock()
	defer s.access.RUnlock()
	return adapter.RuleSetProviderSnapshot{
		Type:      s.options.Type,
		Format:    s.contentFormat,
		UpdatedAt: s.lastUpdated,
		Revision:  s.revision,
		IPCIDR:    s.ipCIDRExport,
	}
}

func (s *RemoteRuleSet) updatedAt() time.Time {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.lastUpdated
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte, lastUpdated time.Time, lastEtag string) error {
	plainRuleSet, contentFormat, err := convertor.Read(bytes.NewReader(content), s.options.Format)
	if err != nil {
		return err
	}
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(plainRuleSet.Rules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return err
	}
	ipCIDRExport := emptyRuleSetIPCIDRExport()
	if metadata.ContainsIPCIDRRule {
		ipCIDRExport = buildRuleSetIPCIDRExport(plainRuleSet.Rules)
	}
	s.access.Lock()
	s.metadata = metadata
	s.ipCIDRExport = ipCIDRExport
	s.contentFormat = contentFormat
	s.rules = rules
	s.lastUpdated = lastUpdated
	s.lastEtag = lastEtag
	s.revision++
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

// Update downloads the rule-set now, whatever its update_interval.
func (s *RemoteRuleSet) Update() error {
	_, err := s.update()
	return err
}

func (s *RemoteRuleSet) updateOnce() bool {
	loaded, _ := s.update()
	return loaded
}

func (s *RemoteRuleSet) update() (bool, error) {
	loaded, err := s.fetch(s.ctx, false)
	if err != nil {
		if s.ctx.Err() == nil {
			s.fetchFailed(err)
		}
		return false, err
	}
	s.failureAccess.Lock()
	if s.failures > 0 {
		s.logger.Info("fetch rule-set ", s.tag, ": succeeded after ", s.failures, " failed attempts")
		s.failures = 0
	}
	s.failureAccess.Unlock()
	s.Cleanup()
	return loaded, nil
}

const ruleSetFailureLogInterval = 10 * time.Minute

// fetchFailed logs the first failure of a series as an error, then a count every
// ruleSetFailureLogInterval, the others at debug.
func (s *RemoteRuleSet) fetchFailed(err error) {
	s.failureAccess.Lock()
	defer s.failureAccess.Unlock()
	s.failures++
	switch {
	case s.failures == 1:
		s.failureLogged = time.Now()
		s.logger.Error("fetch rule-set ", s.tag, ": ", logText(err))
	case time.Since(s.failureLogged) >= ruleSetFailureLogInterval:
		s.failureLogged = time.Now()
		s.logger.Error("fetch rule-set ", s.tag, ": ", s.failures, " failed attempts, the last: ", logText(err))
	default:
		s.logger.Debug("fetch rule-set ", s.tag, ": ", logText(err))
	}
}

// logText makes one printable line, cut short, of an error that may carry what the server sent.
func logText(err error) string {
	text := err.Error()
	if len(text) > 512 {
		text = strings.ToValidUTF8(text[:512], "") + "..."
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, text)
}

// The inbounds listen only after every rule-set has started, so the start gets a total
// deadline; any fetch ends when the transfer stalls, so a slow but steady one still loads.
var (
	ruleSetStartDeadline = 30 * time.Second
	ruleSetStallTimeout  = 30 * time.Second
	ruleSetMaxSize       = 50 << 20
)

// stallResetReader resets the stall timer on every read that carries data.
type stallResetReader struct {
	reader io.Reader
	reset  func()
}

func (r *stallResetReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.reset()
	}
	return n, err
}

// readRuleSetBody refuses what cannot be a rule-set before holding it: a declared length over
// the cap, or a binary body without the magic bytes (a page served with status 200).
func (s *RemoteRuleSet) readRuleSetBody(response *http.Response, body io.Reader) ([]byte, error) {
	if response.ContentLength > int64(ruleSetMaxSize) {
		return nil, E.New("rule-set larger than ", ruleSetMaxSize>>20, " MB")
	}
	reader := bufio.NewReader(io.LimitReader(body, int64(ruleSetMaxSize)+1))
	if s.options.Format == C.RuleSetFormatBinary {
		head, err := reader.Peek(len(srs.MagicBytes))
		if err != nil && err != io.EOF {
			return nil, err
		}
		if !bytes.Equal(head, srs.MagicBytes[:]) {
			sample, _ := reader.Peek(ruleSetSampleSize)
			return nil, E.New("not a binary rule-set: ", describeRuleSetBody(response, response.ContentLength, sample))
		}
	}
	capacity := 512
	if response.ContentLength > 0 {
		// one byte more: the read that finds the end must not regrow the slice
		capacity = int(response.ContentLength) + 1
	}
	content := make([]byte, 0, capacity)
	for {
		if len(content) == cap(content) {
			content = append(content, 0)[:len(content)]
		}
		n, err := reader.Read(content[len(content):cap(content)])
		content = content[:len(content)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(content) > ruleSetMaxSize {
		return nil, E.New("rule-set larger than ", ruleSetMaxSize>>20, " MB")
	}
	return content, nil
}

const ruleSetSampleSize = 16

// describeRuleSetBody tells a page from a damaged file: the size, the declared type and the
// first bytes, quoted as the server sent them.
func describeRuleSetBody(response *http.Response, size int64, sample []byte) string {
	var description strings.Builder
	if size >= 0 {
		description.WriteString(strconv.FormatInt(size, 10))
		description.WriteString(" bytes, ")
	}
	contentType := response.Header.Get("Content-Type")
	if len(contentType) > 64 {
		contentType = contentType[:64]
	}
	description.WriteString("Content-Type ")
	description.WriteString(strconv.Quote(contentType))
	if len(sample) > ruleSetSampleSize {
		sample = sample[:ruleSetSampleSize]
	}
	description.WriteString(", starts with ")
	description.WriteString(strconv.Quote(string(sample)))
	return description.String()
}

// fetch downloads the list and reports whether a new one was loaded.
func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) (bool, error) {
	s.updateAccess.Lock()
	defer s.updateAccess.Unlock()
	err := s.ctx.Err()
	if err != nil {
		return false, err
	}
	s.logger.Debug("updating rule-set ", s.tag, " from URL: ", s.url)
	// a group that switches members closes the connections it did not route; this one stays
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if isStart {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, ruleSetStartDeadline)
		defer stop()
	}
	var stalled atomic.Bool
	stall := time.AfterFunc(ruleSetStallTimeout, func() {
		stalled.Store(true)
		cancel()
	})
	defer stall.Stop()
	// name the bound that cut the fetch: the context errors alone read like a shutdown
	describe := func(err error) error {
		if stalled.Load() {
			return E.Cause(err, "no data for ", ruleSetStallTimeout)
		}
		if isStart && errors.Is(err, context.DeadlineExceeded) {
			return E.Cause(err, "start deadline of ", ruleSetStartDeadline, " reached")
		}
		return err
	}
	request, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return false, err
	}
	s.access.RLock()
	lastEtag := s.lastEtag
	s.access.RUnlock()
	if lastEtag != "" {
		request.Header.Set("If-None-Match", lastEtag)
	}
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	response, err := s.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		if isStart {
			// the start fetches share pooled connections, and a stalled one would hold the next
			s.httpClient.Transport.(adapter.HTTPTransport).Reset()
		}
		return false, describe(err)
	}
	defer response.Body.Close()
	stall.Reset(ruleSetStallTimeout)
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.access.Lock()
		s.lastUpdated = time.Now()
		lastUpdated := s.lastUpdated
		s.access.Unlock()
		if s.cacheFile != nil {
			savedRuleSet := s.cacheFile.LoadRuleSet(s.tag)
			if savedRuleSet != nil {
				savedRuleSet.LastUpdated = lastUpdated
				savedRuleSet.URLHash = s.urlHash[:]
				err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return false, nil
				}
			}
		}
		s.logger.Info("update rule-set ", s.tag, ": not modified")
		return false, nil
	default:
		return false, E.New("unexpected status: ", response.Status)
	}
	body := &stallResetReader{reader: response.Body, reset: func() { stall.Reset(ruleSetStallTimeout) }}
	content, err := s.readRuleSetBody(response, body)
	// the transfer is over: parsing a large list must not look like a stalled download
	stall.Stop()
	if err != nil {
		return false, describe(err)
	}
	// a rule-set closed meanwhile does not parse: a box that replaces it fetches its own
	if s.ctx.Err() != nil {
		return false, s.ctx.Err()
	}
	eTagHeader := response.Header.Get("Etag")
	lastUpdated := time.Now()
	err = s.loadBytes(content, lastUpdated, eTagHeader)
	if err != nil {
		return false, E.Cause(err, "read rule-set (", describeRuleSetBody(response, int64(len(content)), content), ")")
	}
	if s.ctx.Err() != nil {
		// closed during the parse: its cache file is closed too
		return false, s.ctx.Err()
	}
	if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{
			LastUpdated: lastUpdated,
			Content:     content,
			LastEtag:    eTagHeader,
			URLHash:     s.urlHash[:],
		})
		if err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.Info("updated rule-set ", s.tag)
	return true, nil
}

func (s *RemoteRuleSet) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.options.RemoteOptions.HTTPClient != nil && !s.options.RemoteOptions.HTTPClient.IsEmpty() {
		if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.options.RemoteOptions.HTTPClient)
	}
	if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
		deprecated.Report(s.ctx, deprecated.OptionLegacyRuleSetDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.options.RemoteOptions.DownloadDetour, //nolint:staticcheck
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *RemoteRuleSet) Close() error {
	s.cancel()
	s.updateAccess.Lock()
	s.access.Lock()
	s.rules = nil
	s.access.Unlock()
	s.updateAccess.Unlock()
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return matchAnyHeadlessRule(s.rules, metadata)
}

func (s *RemoteRuleSet) mergeableRule() *DefaultHeadlessRule {
	s.access.RLock()
	defer s.access.RUnlock()
	return mergeableRuleIn(s.rules)
}
