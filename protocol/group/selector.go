package group

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

// historyStorage returns the URL test history shared with the Clash API, or a
// private one when no Clash API is running.
func historyStorage(ctx context.Context) *urltest.HistoryStorage {
	if history := service.PtrFromContext[urltest.HistoryStorage](ctx); history != nil {
		return history
	}
	return urltest.NewHistoryStorage()
}

func providerOutboundFilterTag(providerTag, outboundTag string) string {
	return strings.TrimPrefix(outboundTag, providerTag+"/")
}

// excludedOutboundTypes indexes the outbound types a group refuses, so its
// provider members can be filtered by protocol as well as by name.
func excludedOutboundTypes(types []string) map[string]bool {
	if len(types) == 0 {
		return nil
	}
	result := make(map[string]bool, len(types))
	for _, outboundType := range types {
		outboundType = strings.ToLower(strings.TrimSpace(outboundType))
		if outboundType != "" {
			result[outboundType] = true
		}
	}
	return result
}

type providerCallbackRegistration struct {
	provider adapter.Provider
	element  *list.Element[adapter.ProviderUpdateCallback]
}

func registerProviderCallback(provider adapter.Provider, callback adapter.ProviderUpdateCallback) providerCallbackRegistration {
	return providerCallbackRegistration{provider: provider, element: provider.RegisterCallback(callback)}
}

func unregisterProviderCallbacks(registrations []providerCallbackRegistration) {
	for _, registration := range registrations {
		if registration.element != nil {
			registration.provider.UnregisterCallback(registration.element)
		}
	}
}

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup           = (*Selector)(nil)
	_ adapter.ConnectionHandler       = (*Selector)(nil)
	_ adapter.PacketConnectionHandler = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.RWMutex

	provider          adapter.ProviderManager
	providers         map[string]adapter.Provider
	providerCallbacks []providerCallbackRegistration
	outboundsCache    map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	excludeTypes    map[string]bool
	useAllProviders bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         append([]string(nil), options.Outbounds...),
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		excludeTypes:    excludedOutboundTypes(options.ExcludeTypes),
		useAllProviders: options.UseAllProviders,
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start(stage adapter.StartStage, scope *adapter.Scope) (err error) {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(s.Close)
	defer func() {
		if err != nil {
			unregisterProviderCallbacks(s.providerCallbacks)
			s.providerCallbacks = nil
		}
	}()
	if (s.useAllProviders || len(s.providerTags) > 0) && s.provider == nil {
		return E.New("outbound provider manager unavailable")
	}
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
	}
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}
	for i, tag := range s.Dependencies() {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}
	outbound, err := s.outboundSelect()
	if err != nil {
		return err
	}
	s.selected.Store(outbound)
	return nil
}

func (s *Selector) Close() error {
	unregisterProviderCallbacks(s.providerCallbacks)
	s.providerCallbacks = nil
	return nil
}

func (s *Selector) Now() string {
	selected := s.selected.Load()
	if selected == nil {
		s.access.RLock()
		defer s.access.RUnlock()
		if len(s.tags) == 0 {
			return ""
		}
		return s.tags[0]
	}
	return selected.Tag()
}

func (s *Selector) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return append([]string(nil), s.tags...)
}

func (s *Selector) References() []string {
	return []string{s.Now()}
}

func (s *Selector) SelectOutbound(tag string) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	detour, loaded := s.outbounds[tag]
	if !loaded {
		return false
	}
	if s.selected.Swap(detour) == detour {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	selected := s.selected.Load()
	if selected == nil {
		return nil, E.New("no available outbounds")
	}
	conn, err := selected.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	selected := s.selected.Load()
	if selected == nil {
		return nil, E.New("no available outbounds")
	}
	conn, err := selected.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	conn = s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx))
	if selected == nil {
		s.connection.NewConnection(ctx, s, conn, metadata, onClose)
		return
	}
	if outboundHandler, isHandler := selected.(adapter.ConnectionHandler); isHandler {
		outboundHandler.NewConnection(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewConnection(ctx, s, conn, metadata, onClose)
	}
}

func (s *Selector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	conn = s.interruptGroup.NewSingPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx))
	if selected == nil {
		s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
		return
	}
	if outboundHandler, isHandler := selected.(adapter.PacketConnectionHandler); isHandler {
		outboundHandler.NewPacketConnection(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
	}
}

func RealTag(outboundManager adapter.OutboundManager, detour adapter.Outbound) string {
	tag := detour.Tag()
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup || group.Now() == "" {
			return tag
		}
		tag = group.Now()
		var loaded bool
		detour, loaded = outboundManager.Outbound(tag)
		if !loaded {
			return tag
		}
	}
}

func (s *Selector) onProviderUpdated(tag string) error {
	s.access.Lock()
	defer s.access.Unlock()
	_, loaded := s.providers[tag]
	if !loaded {
		return E.New(s.Tag(), ": ", "outbound provider not found: ", tag)
	}
	var (
		tags          = append([]string(nil), s.Dependencies()...)
		outboundByTag = make(map[string]adapter.Outbound)
	)
	for _, tag := range tags {
		outboundByTag[tag] = s.outbounds[tag]
	}
	for _, providerTag := range s.providerTags {
		if providerTag != tag && s.outboundsCache[providerTag] != nil {
			for _, detour := range s.outboundsCache[providerTag] {
				tags = append(tags, detour.Tag())
				outboundByTag[detour.Tag()] = detour
			}
			continue
		}
		provider := s.providers[providerTag]
		var cache []adapter.Outbound
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			filterTag := providerOutboundFilterTag(providerTag, tag)
			if s.excludeTypes[detour.Type()] {
				continue
			}
			if s.exclude != nil && s.exclude.MatchString(filterTag) {
				continue
			}
			if s.include != nil && !s.include.MatchString(filterTag) {
				continue
			}
			tags = append(tags, tag)
			cache = append(cache, detour)
			outboundByTag[tag] = detour
		}
		s.outboundsCache[providerTag] = cache
	}
	s.tags, s.outbounds = tags, outboundByTag
	detour, err := s.outboundSelect()
	if s.selected.Swap(detour) != detour {
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
	}
	return err
}

func (s *Selector) outboundSelect() (adapter.Outbound, error) {
	if len(s.tags) == 0 {
		return nil, nil
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := s.outbounds[selected]
				if loaded {
					return detour, nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.outbounds[s.defaultTag]
		if !loaded {
			return nil, E.New("default outbound not found: ", s.defaultTag)
		}
		return detour, nil
	}

	return s.outbounds[s.tags[0]], nil
}
