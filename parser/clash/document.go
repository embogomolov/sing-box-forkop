package clash

import (
	"encoding/json"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

// A Clash proxy is read the way Clash reads one: option names normalised, then decoded into the
// protocol's options. Keys the protocol does not define are ignored, as Clash ignores them, since
// generators write one key set for every proxy.
func proxyContent(node *yaml.Node) (json.RawMessage, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	object, isObject := value.(map[string]any)
	if !isObject {
		return nil, E.New("proxy is not a mapping")
	}
	content, err := json.Marshal(normalizeKeys(object, false))
	if err != nil {
		return nil, err
	}
	return content, nil
}

// verbatimKeys names the option blocks whose keys are data rather than option
// names - HTTP header names and plugin arguments are passed on as written.
var verbatimKeys = map[string]bool{
	"headers":     true,
	"ws-headers":  true,
	"plugin-opts": true,
	"obfs-opts":   true,
}

// normalizeKeys lowercases option names and accepts the underscore spelling,
// the way Clash matches a configuration key against a field name.
func normalizeKeys(value any, verbatim bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			normalizedKey := key
			if !verbatim {
				normalizedKey = strings.ReplaceAll(strings.ToLower(key), "_", "-")
			}
			result[normalizedKey] = normalizeKeys(child, verbatimKeys[normalizedKey])
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = normalizeKeys(child, verbatim)
		}
		return result
	default:
		return value
	}
}

func decodeProxy(content json.RawMessage, options any) error {
	if err := json.Unmarshal(content, options); err != nil {
		return err
	}
	if validator, isValidator := options.(interface{ Validate() error }); isValidator {
		return validator.Validate()
	}
	return nil
}
