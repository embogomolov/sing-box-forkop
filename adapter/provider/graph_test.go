package provider

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestPrepareProviderGraph(t *testing.T) {
	source := []option.Outbound{
		{
			Type: C.TypeVLESS,
			Tag:  "primary",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "hop"},
			},
		},
		{Type: C.TypeVLESS, Tag: "hop", Options: &option.VLESSOutboundOptions{}},
	}

	prepared, err := prepareOutbounds("subscription", source, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 || prepared[0].tag != "subscription/hop" || prepared[1].tag != "subscription/primary" {
		t.Fatalf("unexpected dependency order: %v", preparedTags(prepared))
	}
	primary := prepared[1].runtime.Options.(*option.VLESSOutboundOptions)
	if primary.Detour != "subscription/hop" {
		t.Fatalf("internal detour was not namespaced: %q", primary.Detour)
	}
	if source[0].Options.(*option.VLESSOutboundOptions).Detour != "hop" {
		t.Fatal("preparing a provider graph must not mutate source options")
	}

	updated := append([]option.Outbound(nil), source...)
	updatedHop := *source[1].Options.(*option.VLESSOutboundOptions)
	updatedHop.UUID = "changed"
	updated[1].Options = &updatedHop
	newPrepared, err := prepareOutbounds("subscription", updated, "")
	if err != nil {
		t.Fatal(err)
	}
	affected := affectedOutbounds(prepared, newPrepared)
	for _, tag := range []string{"subscription/hop", "subscription/primary"} {
		if !affected[tag] {
			t.Fatalf("dependent outbound %q was not marked for recreation", tag)
		}
	}
}

func TestPrepareProviderGraphAppliesDefaultDetourOnlyWhenEmpty(t *testing.T) {
	source := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "plain", Options: &option.VLESSOutboundOptions{}},
		{
			Type: C.TypeVLESS,
			Tag:  "chained",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "hop"},
			},
		},
		{Type: C.TypeSOCKS, Tag: "hop", Options: &option.SOCKSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "external", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "global-egress"}}},
	}
	prepared, err := prepareOutbounds("subscription", source, "cascade")
	if err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]preparedOutbound, len(prepared))
	for _, outbound := range prepared {
		byTag[outbound.tag] = outbound
	}
	if detour := byTag["subscription/plain"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "cascade" {
		t.Fatalf("plain detour = %q, want cascade", detour)
	}
	if detour := byTag["subscription/chained"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "subscription/hop" {
		t.Fatalf("chained detour = %q, want internal hop", detour)
	}
	if detour := byTag["subscription/external"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "global-egress" {
		t.Fatalf("external detour = %q, want global-egress", detour)
	}
	if source[0].Options.(*option.VLESSOutboundOptions).Detour != "" {
		t.Fatal("default detour mutated source options")
	}
}

func TestFilterInvalidOutboundsDropsOnlyBrokenChains(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "hop", Options: &option.SOCKSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "valid", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "hop"}}},
		{Type: C.TypeVLESS, Tag: "through-group", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "group"}}},
		{Type: C.TypeVLESS, Tag: "through-invalid", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "broken"}}},
		{Type: C.TypeVLESS, Tag: "external", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "global-egress"}}},
	}
	filtered := FilterInvalidOutbounds(outbounds, map[string]bool{"group": true, "broken": true})
	if len(filtered) != 3 || filtered[0].Tag != "hop" || filtered[1].Tag != "valid" || filtered[2].Tag != "external" {
		t.Fatalf("unexpected filtered outbounds: %#v", filtered)
	}
}

func TestNormalizeProviderTagsRewritesLeafDetours(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "hop", Options: &option.VLESSOutboundOptions{}},
		{
			Type: C.TypeVLESS,
			Tag:  "node",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "hop"},
			},
		},
	}
	renamed, err := newOverride(option.ProviderOverrideOptions{Prefix: "DE "})
	if err != nil {
		t.Fatal(err)
	}
	normalizeOutboundTags(outbounds, false, renamed)
	if outbounds[0].Tag != "DE hop" || outbounds[1].Options.(*option.VLESSOutboundOptions).Detour != "DE hop" {
		t.Fatalf("tag normalization broke detour: tag=%q detour=%q", outbounds[0].Tag, outbounds[1].Options.(*option.VLESSOutboundOptions).Detour)
	}
}

func TestNormalizeProviderTagsWithoutMutatingSource(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "hop", Options: &option.VLESSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "node", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "hop"}}},
	}
	cloned := cloneOutbounds(outbounds)
	normalizeOutboundTags(cloned, false, nil)
	if cloned[0].Tag != "hop" || cloned[1].Options.(*option.VLESSOutboundOptions).Detour != "hop" {
		t.Fatalf("tag normalization broke detour: tags=%q,%q detour=%q", cloned[0].Tag, cloned[1].Tag, cloned[1].Options.(*option.VLESSOutboundOptions).Detour)
	}
	if outbounds[0].Tag != "hop" || outbounds[1].Options.(*option.VLESSOutboundOptions).Detour != "hop" {
		t.Fatal("provider tag normalization mutated source options")
	}
}

type stageRecordingOutbound struct {
	adapter.Outbound
	outboundAdapter.Adapter
	stages  []adapter.StartStage
	onStart func(stage adapter.StartStage)
}

func (o *stageRecordingOutbound) Type() string           { return o.Adapter.Type() }
func (o *stageRecordingOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *stageRecordingOutbound) Network() []string      { return o.Adapter.Network() }
func (o *stageRecordingOutbound) Dependencies() []string { return o.Adapter.Dependencies() }

func (o *stageRecordingOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	o.stages = append(o.stages, stage)
	if o.onStart != nil {
		o.onStart(stage)
	}
	return nil
}

func (o *stageRecordingOutbound) Close() error {
	return nil
}

func newStageTestProvider(t *testing.T, onStart func(tag string, stage adapter.StartStage)) (*Adapter, *outboundAdapter.Manager, *adapter.Scope, map[string]*stageRecordingOutbound) {
	created := make(map[string]*stageRecordingOutbound)
	registry := outboundAdapter.NewRegistry()
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, "recording", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.VLESSOutboundOptions) (adapter.Outbound, error) {
		outbound := &stageRecordingOutbound{Adapter: outboundAdapter.NewAdapter("recording", tag, nil, nil)}
		if onStart != nil {
			outbound.onStart = func(stage adapter.StartStage) { onStart(tag, stage) }
		}
		created[tag] = outbound
		return outbound, nil
	})
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	scope := adapter.NewScope(context.Background(), logger)
	// The outbound manager starts an outbound with a lifecycle through the
	// endpoint manager, which takes its scope at initialization, as in the box.
	endpoints := endpoint.NewManager(nil)
	if err := endpoints.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	manager := outboundAdapter.NewManager(registry, endpoints, "")
	if err := manager.Create(ctx, nil, logger, "direct", "recording", &option.VLESSOutboundOptions{}); err != nil {
		t.Fatal(err)
	}
	provider := &Adapter{
		ctx:         ctx,
		outbound:    manager,
		logFactory:  logFactory,
		logger:      logger,
		providerTag: "subscription",
	}
	return provider, manager, scope, created
}

func TestProviderOutboundsRunEveryStartStageOnce(t *testing.T) {
	provider, manager, scope, created := newStageTestProvider(t, nil)
	startStage := func(stage adapter.StartStage) {
		if err := manager.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	cached := option.Outbound{Type: "recording", Tag: "cached", Options: &option.VLESSOutboundOptions{}}
	fetched := option.Outbound{Type: "recording", Tag: "fetched", Options: &option.VLESSOutboundOptions{}}

	startStage(adapter.StartStateInitialize)
	startStage(adapter.StartStateStart)
	if err := provider.UpdateOutbounds([]option.Outbound{cached}); err != nil {
		t.Fatal(err)
	}
	startStage(adapter.StartStatePostStart)
	startStage(adapter.StartStateStarted)
	if err := provider.UpdateOutbounds([]option.Outbound{cached, fetched}); err != nil {
		t.Fatal(err)
	}

	for _, tag := range []string{"direct", "subscription/cached", "subscription/fetched"} {
		if stages := created[tag].stages; !reflect.DeepEqual(stages, adapter.ListStartStages) {
			t.Fatalf("%s ran the start stages %v, want %v", tag, stages, adapter.ListStartStages)
		}
	}
}

func TestProviderUpdateHoldsTheNextStartStageBack(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	provider, manager, scope, created := newStageTestProvider(t, func(tag string, stage adapter.StartStage) {
		if tag == "subscription/fetched" && stage == adapter.StartStateStart {
			close(entered)
			<-release
		}
	})
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart} {
		if err := manager.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- provider.UpdateOutbounds([]option.Outbound{{Type: "recording", Tag: "fetched", Options: &option.VLESSOutboundOptions{}}})
	}()
	<-entered
	postStartDone := make(chan error, 1)
	go func() {
		postStartDone <- manager.Start(adapter.StartStatePostStart, scope)
	}()
	select {
	case <-postStartDone:
		close(release)
		t.Fatal("the manager ran post-start while the provider was starting its outbounds")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-postStartDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-start stage did not finish after the provider update")
	}
	want := []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart}
	if stages := created["subscription/fetched"].stages; !reflect.DeepEqual(stages, want) {
		t.Fatalf("fetched ran the start stages %v, want %v", stages, want)
	}
}

func preparedTags(outbounds []preparedOutbound) []string {
	result := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		result = append(result, outbound.tag)
	}
	return result
}
