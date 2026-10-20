package provider

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProviderLocal(registry *provider.Registry) {
	provider.Register[option.ProviderLocalOptions](registry, C.ProviderTypeLocal, NewProviderLocal)
}

func RegisterProviderInline(registry *provider.Registry) {
	provider.Register[option.ProviderInlineOptions](registry, C.ProviderTypeInline, NewProviderInline)
}

var _ adapter.Provider = (*ProviderLocal)(nil)

type ProviderLocal struct {
	provider.Adapter
	ctx         context.Context
	logger      log.ContextLogger
	provider    adapter.ProviderManager
	path        string
	exclude     *regexp.Regexp
	include     *regexp.Regexp
	lastUpdated time.Time
	watcher     *fswatch.Watcher
}

func NewProviderInline(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderInlineOptions) (adapter.Provider, error) {
	var (
		outbound = service.FromContext[adapter.OutboundManager](ctx)
		logger   = logFactory.NewLogger(F.ToString("provider/inline", "[", tag, "]"))
	)
	p := &ProviderLocal{
		Adapter: provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeInline, options.HealthCheck),
		ctx:     ctx,
		logger:  logger,
	}
	p.SetRemoveEmojis(options.RemoveEmojis)
	p.SetOverrideDialerOptions(options.OverrideDialerOptions)
	if err := p.SetOverride(options.Override); err != nil {
		return nil, err
	}
	outbounds, err := p.FilterOutbounds(options.Outbounds, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := p.UpdateOutbounds(outbounds); err != nil {
		return nil, err
	}
	return p, nil
}

func NewProviderLocal(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderLocalOptions) (adapter.Provider, error) {
	if options.Path == "" {
		return nil, E.New("provider path is required")
	}
	var (
		outbound = service.FromContext[adapter.OutboundManager](ctx)
		logger   = logFactory.NewLogger(F.ToString("provider/local", "[", tag, "]"))
	)
	provider := &ProviderLocal{
		Adapter:  provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeLocal, options.HealthCheck),
		ctx:      ctx,
		logger:   logger,
		provider: service.FromContext[adapter.ProviderManager](ctx),
		exclude:  (*regexp.Regexp)(options.Exclude),
		include:  (*regexp.Regexp)(options.Include),
	}
	provider.SetRemoveEmojis(options.RemoveEmojis)
	provider.SetOverrideDialerOptions(options.OverrideDialerOptions)
	provider.SetExcludeTypes(options.ExcludeTypes)
	if err := provider.SetOverride(options.Override); err != nil {
		return nil, err
	}
	filePath := filemanager.BasePath(ctx, options.Path)
	provider.path, _ = filepath.Abs(filePath)
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{filePath},
		Callback: func(path string) {
			uErr := provider.reloadFile(path)
			if uErr != nil {
				logger.Error(E.Cause(uErr, "reload provider ", tag))
			}
		},
	})
	if err != nil {
		return nil, err
	}
	provider.watcher = watcher
	return provider, nil
}

func (s *ProviderLocal) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(s.Close)
	if s.path != "" {
		if err := s.reloadFile(s.path); err != nil {
			s.logger.Error(E.Cause(err, "load provider file"))
		}
	} else {
		s.UpdateGroups()
	}
	err := s.Adapter.Start()
	if err != nil {
		return err
	}
	if s.watcher != nil {
		err = s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch provider file"))
		}
	}
	return nil
}

func (s *ProviderLocal) UpdatedAt() time.Time {
	return s.lastUpdated
}

func (s *ProviderLocal) reloadFile(path string) error {
	if fileInfo, err := os.Stat(path); err == nil {
		s.lastUpdated = fileInfo.ModTime()
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	parsed, err := parser.ParseSubscription(s.ctx, string(content))
	subscription.ReportSkipped(s.logger, s.Tag(), parsed)
	if err != nil {
		return err
	}
	outboundOpts, err := s.FilterOutbounds(parsed.Outbounds, s.exclude, s.include)
	if err != nil {
		return err
	}
	if err := s.UpdateOutbounds(outboundOpts); err != nil {
		return err
	}
	return nil
}

func (s *ProviderLocal) Close() error {
	return common.Close(common.PtrOrNil(s.watcher), &s.Adapter)
}
