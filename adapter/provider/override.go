package provider

import (
	"context"
	"reflect"
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// override rewrites the outbounds a provider imports before they are turned
// into runtime outbounds.
type override struct {
	prefix  string
	suffix  string
	renames []renameRule
	detour  string
	patch   map[string]any
}

type renameRule struct {
	pattern *regexp.Regexp
	target  string
}

func newOverride(options option.ProviderOverrideOptions) (*override, error) {
	result := &override{
		prefix: options.Prefix,
		suffix: options.Suffix,
		detour: options.Detour,
		patch:  options.Patch,
	}
	for index, rename := range options.Rename {
		if rename.Pattern == nil {
			return nil, E.New("missing pattern in override rename rule ", index+1)
		}
		pattern := (*regexp.Regexp)(rename.Pattern)
		// An empty pattern matches between every character, so it would spread
		// the target through every tag instead of renaming anything.
		if pattern.String() == "" {
			return nil, E.New("empty pattern in override rename rule ", index+1)
		}
		result.renames = append(result.renames, renameRule{
			pattern: pattern,
			target:  rename.Target,
		})
	}
	return result, nil
}

// ApplyTag rewrites a source tag. The rename rules run in order and each one
// observes the result of the previous, then the prefix and suffix are added.
func (o *override) ApplyTag(tag string) string {
	if o == nil {
		return tag
	}
	for _, rename := range o.renames {
		tag = rename.pattern.ReplaceAllString(tag, rename.target)
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return tag
	}
	return o.prefix + tag + o.suffix
}

// ApplyOptions merges the patch into the options of one outbound.
func (o *override) ApplyOptions(ctx context.Context, outbound option.Outbound) (option.Outbound, error) {
	if o == nil || len(o.patch) == 0 {
		return outbound, nil
	}
	return applyPatch(ctx, outbound, o.patch)
}

// applyPatch merges a JSON merge patch into one outbound. Keys the outbound
// type does not declare are skipped instead of failing the node, so a patch
// written for one protocol leaves the others of a mixed subscription alone.
func applyPatch(ctx context.Context, outbound option.Outbound, patch map[string]any) (option.Outbound, error) {
	allowed, err := declaredOutboundFields(ctx, outbound.Type)
	if err != nil {
		return outbound, err
	}
	applicable := make(map[string]any)
	for key, value := range patch {
		if allowed[key] {
			applicable[key] = value
		}
	}
	if len(applicable) == 0 {
		return outbound, nil
	}
	// Outbound only carries its options through the pointer marshaler, so the
	// value has to be addressable here.
	content, err := json.MarshalContext(ctx, &outbound)
	if err != nil {
		return outbound, E.Cause(err, "encode outbound for override patch")
	}
	var document map[string]any
	if err = json.Unmarshal(content, &document); err != nil {
		return outbound, E.Cause(err, "decode outbound for override patch")
	}
	mergePatch(document, applicable)
	content, err = json.Marshal(document)
	if err != nil {
		return outbound, E.Cause(err, "encode patched outbound")
	}
	var patched option.Outbound
	if err = json.UnmarshalContext(ctx, content, &patched); err != nil {
		return outbound, E.Cause(err, "decode patched outbound")
	}
	return patched, nil
}

// mergePatch implements RFC 7386: objects are merged recursively, null removes
// a key and every other value replaces the current one.
func mergePatch(target map[string]any, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			delete(target, key)
			continue
		}
		patchObject, isObject := value.(map[string]any)
		if !isObject {
			target[key] = value
			continue
		}
		targetObject, loaded := target[key].(map[string]any)
		if !loaded {
			targetObject = make(map[string]any)
			target[key] = targetObject
		}
		mergePatch(targetObject, patchObject)
	}
}

// declaredOutboundFields lists the JSON fields an outbound type accepts, so a
// patch key that the type would reject is dropped before it is applied.
func declaredOutboundFields(ctx context.Context, outboundType string) (map[string]bool, error) {
	registry := service.FromContext[adapter.OutboundRegistry](ctx)
	if registry == nil {
		return nil, E.New("missing outbound registry")
	}
	options, loaded := registry.CreateOptions(outboundType)
	if !loaded {
		return nil, E.New("unknown outbound type: ", outboundType)
	}
	result := make(map[string]bool)
	collectJSONFields(reflect.TypeOf(options), result)
	// The provider owns the identity of its outbounds.
	delete(result, "type")
	delete(result, "tag")
	return result, nil
}

func collectJSONFields(value reflect.Type, result map[string]bool) {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value == nil || value.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			collectJSONFields(field.Type, result)
			continue
		}
		if name == "" {
			name = field.Name
		}
		result[name] = true
	}
}
