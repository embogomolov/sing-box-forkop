package rule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	convertor "github.com/sagernet/sing-box/common/convertor/ruleset"
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

const ruleSetFetchTimeout = 4 * C.TCPTimeout

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
		err = s.fetch(ctx, true)
		if err != nil {
			s.logger.Error(E.Cause(err, "initial rule-set ", s.tag, " unavailable, continuing without it"))
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

func (s *RemoteRuleSet) Update() error {
	err := s.fetch(s.ctx, false)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.tag, ": ", err)
		return err
	}
	s.Cleanup()
	return nil
}

func (s *RemoteRuleSet) updateOnce() {
	_ = s.Update()
}

func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) error {
	s.updateAccess.Lock()
	defer s.updateAccess.Unlock()
	err := s.ctx.Err()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, ruleSetFetchTimeout)
	defer cancel()
	s.logger.Debug("updating rule-set ", s.tag, " from URL: ", s.url)
	request, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
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
		return err
	}
	defer response.Body.Close()
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
					return nil
				}
			}
		}
		s.logger.Info("update rule-set ", s.tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	eTagHeader := response.Header.Get("Etag")
	lastUpdated := time.Now()
	err = s.loadBytes(content, lastUpdated, eTagHeader)
	if err != nil {
		return err
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
	return nil
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
