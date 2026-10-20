package singbox

import (
	"context"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

// plumbingTypes are the outbounds a sing-box configuration carries beside its
// servers. Dialling through direct is dialling directly; the rest either drop
// traffic or pick between other outbounds, and a provider imports servers, not
// the selection the author of the configuration made.
var plumbingTypes = map[string]bool{
	C.TypeDirect:   true,
	C.TypeBlock:    true,
	C.TypeDNS:      true,
	C.TypeSelector: true,
	C.TypeURLTest:  true,
	C.TypeFallback: true,
}

// namesOutboundTypes reports whether the outbounds are sing-box's. An Xray
// document is an object with an outbounds array as well, and its entries name a
// protocol rather than a type; deciding which format this is before importing
// anything keeps one from being read as the other.
func namesOutboundTypes(outbounds badjson.JSONArray) bool {
	for _, rawOutbound := range outbounds {
		object, isObject := rawOutbound.(*badjson.JSONObject)
		if !isObject {
			continue
		}
		if value, hasType := object.Get("type"); hasType {
			if _, isString := value.(string); isString {
				return true
			}
		}
	}
	return false
}

func ParseBoxSubscription(ctx context.Context, content string) (subscription.Result, error) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	var document badjson.JSONObject
	if err := document.UnmarshalJSONContext(ctx, []byte(trimmed)); err != nil {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	rawValue, hasOutbounds := document.Get("outbounds")
	if !hasOutbounds {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	rawOutbounds, isArray := rawValue.(badjson.JSONArray)
	if !isArray || !namesOutboundTypes(rawOutbounds) {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	collector := subscription.NewCollector("sing-box")
	for index, rawOutbound := range rawOutbounds {
		outboundObject, isObject := rawOutbound.(*badjson.JSONObject)
		if !isObject {
			collector.Skip("", collector.Label(index, ""), E.New("outbound is not an object"))
			continue
		}
		tagValue, _ := outboundObject.Get("tag")
		tag, _ := tagValue.(string)
		label := collector.Label(index, tag)
		typeValue, hasType := outboundObject.Get("type")
		if !hasType {
			collector.Skip(tag, label, E.New("missing type"))
			continue
		}
		outboundType, isString := typeValue.(string)
		if !isString {
			collector.Skip(tag, label, E.New("type is not a string"))
			continue
		}
		if plumbingTypes[outboundType] {
			if outboundType == C.TypeDirect {
				collector.Direct(tag)
			} else {
				collector.Discard(tag)
			}
			continue
		}
		outboundContent, err := outboundObject.MarshalJSONContext(ctx)
		if err != nil {
			collector.Skip(tag, label, err)
			continue
		}
		var outbound option.Outbound
		if err = json.UnmarshalContext(ctx, outboundContent, &outbound); err != nil {
			collector.Skip(tag, label, err)
			continue
		}
		collector.Add(outbound)
	}
	return collector.Result(), nil
}
