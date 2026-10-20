package provider

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	linkParser "github.com/sagernet/sing-box/parser/link"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	ctx            context.Context
	outbound       adapter.OutboundManager
	router         adapter.Router
	logFactory     log.Factory
	logger         log.ContextLogger
	providerType   string
	providerTag    string
	outbounds      []adapter.Outbound
	outboundsByTag map[string]adapter.Outbound
	ticker         *time.Ticker
	checking       atomic.Bool
	history        *urltest.HistoryStorage
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	link                  string
	enabled               bool
	removeEmojis          bool
	overrideDialerOptions *option.DialerOptions
	timeout               time.Duration
	interval              time.Duration

	access             sync.RWMutex
	outboundSources    map[string]option.Outbound
	outboundCloseOrder []string
	outboundOpts       []option.Outbound
	excludeTypes       map[string]bool
	override           *override
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return Adapter{
		ctx:          ctx,
		outbound:     outbound,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,

		enabled:  options.Enabled,
		link:     options.URL,
		timeout:  timeout,
		interval: interval,
	}
}

func (a *Adapter) SetRemoveEmojis(remove bool) {
	a.removeEmojis = remove
}

func (a *Adapter) SetExcludeTypes(types []string) {
	if len(types) == 0 {
		a.excludeTypes = nil
		return
	}
	excludeTypes := make(map[string]bool, len(types))
	for _, outboundType := range types {
		outboundType = strings.ToLower(strings.TrimSpace(outboundType))
		if outboundType != "" {
			excludeTypes[outboundType] = true
		}
	}
	a.excludeTypes = excludeTypes
}

func (a *Adapter) SetOverride(options option.ProviderOverrideOptions) error {
	value, err := newOverride(options)
	if err != nil {
		return err
	}
	a.override = value
	return nil
}

func (a *Adapter) SetOverrideDialerOptions(options *option.DialerOptions) {
	a.overrideDialerOptions = options
}

func (a *Adapter) Start() error {
	a.history = service.PtrFromContext[urltest.HistoryStorage](a.ctx)
	if a.history == nil {
		a.history = urltest.NewHistoryStorage()
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	a.access.RLock()
	defer a.access.RUnlock()
	return append([]adapter.Outbound(nil), a.outbounds...)
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	a.access.RLock()
	defer a.access.RUnlock()
	if a.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := a.outboundsByTag[tag]
	return detour, ok
}

func (a *Adapter) OutboundLink(tag string) (string, bool, error) {
	a.access.RLock()
	source, loaded := a.outboundSources[tag]
	a.access.RUnlock()
	if !loaded {
		return "", false, nil
	}
	link, err := linkParser.GenerateSubscriptionLink(source)
	return link, true, err
}

// UpdateOutbounds publishes outbounds that FilterOutbounds already rewrote, so
// the provider override is never applied twice to the same tag.
func (a *Adapter) UpdateOutbounds(newOpts []option.Outbound) error {
	sourceOpts := FilterInvalidOutbounds(newOpts, nil)
	a.access.RLock()
	oldOpts := cloneOutbounds(a.outboundOpts)
	currentCount := len(a.outbounds)
	a.access.RUnlock()
	// An update that leaves nothing keeps the last published set, so a broken answer does not empty
	// the groups.
	if len(sourceOpts) == 0 && (len(newOpts) > 0 || currentCount > 0) {
		return E.New("no usable provider outbounds")
	}
	newOpts = cloneOutbounds(sourceOpts)
	oldOutbounds, err := prepareOutbounds(a.providerTag, oldOpts, a.defaultDetour())
	if err != nil {
		return err
	}
	newOutbounds, err := prepareOutbounds(a.providerTag, newOpts, a.defaultDetour())
	if err != nil {
		return err
	}
	oldRuntimeOutbounds, scope, appliedOutbounds, err := a.replaceOutbounds(oldOutbounds, newOutbounds)
	if err != nil {
		restoreErr := a.publishOutbounds(oldOutbounds)
		a.UpdateGroups()
		return E.Errors(err, restoreErr)
	}
	if err = a.publishOutbounds(appliedOutbounds); err != nil {
		return err
	}
	a.UpdateGroups()
	for _, oldOutbound := range oldRuntimeOutbounds {
		if err := removeOutbound(scope, oldOutbound); err != nil {
			a.logger.Error("close replaced provider outbound [", oldOutbound.Tag(), "]: ", err)
		}
	}
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
	return nil
}

// FilterOutbounds rewrites the imported outbounds with the provider override
// and then applies the name filters, so a filter matches what the user sees.
func (a *Adapter) FilterOutbounds(opts []option.Outbound, exclude *regexp.Regexp, include *regexp.Regexp) ([]option.Outbound, error) {
	opts, excludedTags := a.filterOutboundTypes(opts)
	opts = cloneOutbounds(FilterInvalidOutbounds(opts, excludedTags))
	for index, outbound := range opts {
		// override_dialer_options replaces the dialer first, and the patch refines it.
		if a.overrideDialerOptions != nil {
			if wrapper, ok := outbound.Options.(option.DialerOptionsWrapper); ok {
				wrapper.ReplaceDialerOptions(*cloneOptions(a.overrideDialerOptions).(*option.DialerOptions))
			}
		}
		patched, err := a.override.ApplyOptions(a.ctx, outbound)
		if err != nil {
			return nil, E.Cause(err, "override outbound ", outbound.Tag)
		}
		opts[index] = patched
	}
	normalizeOutboundTags(opts, a.removeEmojis, a.override)
	if exclude == nil && include == nil {
		return opts, nil
	}
	// Chains that dialed through a filtered-out outbound go with it.
	filteredTags := make(map[string]bool)
	kept := make([]option.Outbound, 0, len(opts))
	for _, outbound := range opts {
		if (exclude != nil && exclude.MatchString(outbound.Tag)) ||
			(include != nil && !include.MatchString(outbound.Tag)) {
			filteredTags[outbound.Tag] = true
			continue
		}
		kept = append(kept, outbound)
	}
	result := FilterInvalidOutbounds(kept, filteredTags)
	if len(result) == 0 && len(opts) > 0 {
		a.logger.Warn("name filter left none of the ", len(opts), " imported outbounds")
	}
	return result, nil
}

func (a *Adapter) defaultDetour() string {
	if a.override == nil {
		return ""
	}
	return a.override.detour
}

// filterOutboundTypes drops the excluded outbound types and reports their tags, so chains through
// them are dropped too.
func (a *Adapter) filterOutboundTypes(opts []option.Outbound) ([]option.Outbound, map[string]bool) {
	if len(a.excludeTypes) == 0 {
		return opts, nil
	}
	excludedTags := make(map[string]bool)
	result := make([]option.Outbound, 0, len(opts))
	for _, outbound := range opts {
		if a.excludeTypes[strings.ToLower(outbound.Type)] {
			if outbound.Tag != "" {
				excludedTags[outbound.Tag] = true
			}
			continue
		}
		result = append(result, outbound)
	}
	return result, excludedTags
}

func (a *Adapter) publishOutbounds(preparedOutbounds []preparedOutbound) error {
	var (
		outbounds          = make([]adapter.Outbound, 0, len(preparedOutbounds))
		outboundsByTag     = make(map[string]adapter.Outbound, len(preparedOutbounds))
		outboundSources    = make(map[string]option.Outbound, len(preparedOutbounds))
		outboundOpts       = make([]option.Outbound, 0, len(preparedOutbounds))
		outboundCloseOrder = make([]string, 0, len(preparedOutbounds))
	)
	for _, prepared := range preparedOutbounds {
		outboundCloseOrder = append(outboundCloseOrder, prepared.tag)
	}
	for _, prepared := range sourceOrder(preparedOutbounds) {
		outbound, loaded := a.outbound.Outbound(prepared.tag)
		if !loaded {
			return E.New("provider outbound not found after update: ", prepared.tag)
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[prepared.tag] = outbound
		outboundSources[prepared.tag] = prepared.source
		outboundOpts = append(outboundOpts, prepared.source)
	}
	a.access.Lock()
	a.outbounds = outbounds
	a.outboundsByTag = outboundsByTag
	a.outboundSources = outboundSources
	a.outboundOpts = outboundOpts
	a.outboundCloseOrder = outboundCloseOrder
	a.access.Unlock()
	return nil
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	a.callbackAccess.Lock()
	var callbacks []adapter.ProviderUpdateCallback
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	a.callbackAccess.Unlock()
	for _, callback := range callbacks {
		if err := callback(a.providerTag); err != nil {
			a.logger.Error("update provider group: ", err)
		}
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	a.access.Lock()
	closeOrder := a.outboundCloseOrder
	a.outbounds = nil
	a.outboundsByTag = nil
	a.outboundSources = nil
	a.outboundCloseOrder = nil
	a.outboundOpts = nil
	a.access.Unlock()
	var err error
	for index := len(closeOrder) - 1; index >= 0; index-- {
		tag := closeOrder[index]
		if err2 := a.outbound.Remove(tag); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", tag, "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	a.healthcheck(a.ctx)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			a.healthcheck(a.ctx)
		}
	}
}

func (a *Adapter) healthcheck(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range a.Outbounds() {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result, nil
}

func normalizeOutboundTags(opts []option.Outbound, removeEmojis bool, tagOverride *override) {
	used := make(map[string]bool, len(opts))
	tags := make(map[string]string)
	for i, opt := range opts {
		originalTag := opt.Tag
		tag := originalTag
		if removeEmojis {
			tag = removeEmojisFromTag(tag)
		}
		tag = tagOverride.ApplyTag(tag)
		if tag == "" {
			tag = F.ToString("Node #", i+1)
		}
		// A repeated name is numbered until it is free, so no two outbounds share a tag.
		if used[tag] {
			base := tag
			for index := 2; used[tag]; index++ {
				tag = F.ToString(base, " #", index)
			}
		}
		used[tag] = true
		opts[i].Tag = tag
		if originalTag != "" {
			if _, exists := tags[originalTag]; !exists {
				tags[originalTag] = tag
			}
		}
	}
	for _, outbound := range opts {
		rewriteOutboundReferences(outbound.Options, tags)
	}
}

func removeEmojisFromTag(tag string) string {
	cleaned := flagRegex.ReplaceAllStringFunc(tag, flagToCountryCode)
	cleaned = emojiRegex.ReplaceAllString(cleaned, "")
	cleaned = multiSpaceRegex.ReplaceAllString(cleaned, " ")
	return strings.TrimSpace(cleaned)
}

func flagToCountryCode(flag string) string {
	runes := []rune(flag)
	if len(runes) == 2 {
		return string(rune(runes[0]-0x1F1E6+'A')) + string(rune(runes[1]-0x1F1E6+'A')) + " "
	}
	return ""
}

var flagRegex = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]{2}`)
var emojiRegex = regexp.MustCompile(`[\x{1F1E0}-\x{1F1FF}\x{1F300}-\x{1F9FF}\x{2600}-\x{27BF}\x{FE00}-\x{FE0F}\x{200D}]+`)
var multiSpaceRegex = regexp.MustCompile(`\s{2,}`)

func cloneOutbounds(outbounds []option.Outbound) []option.Outbound {
	cloned := make([]option.Outbound, len(outbounds))
	for index, outbound := range outbounds {
		cloned[index] = outbound
		cloned[index].Options = cloneOptions(outbound.Options)
	}
	return cloned
}
