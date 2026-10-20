package ruleset

import (
	"bytes"
	"io"

	"github.com/sagernet/sing-box/common/convertor/plain"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// Enough content to recognize a format and to reach the first meaningful byte of
// a source rule-set that carries a comment header.
const autoDetectPrefixBytes = 64 << 10

var utf8BOM = [3]byte{0xEF, 0xBB, 0xBF}

// Read parses a rule-set in the given format and reports the format the content
// turned out to be in, which differs from the requested one only for auto.
func Read(reader io.Reader, format string) (option.PlainRuleSet, string, error) {
	prefixBytes := len(utf8BOM)
	if format == C.RuleSetFormatAuto {
		prefixBytes = autoDetectPrefixBytes
	}
	prefix, err := io.ReadAll(io.LimitReader(reader, int64(prefixBytes)))
	if err != nil {
		return option.PlainRuleSet{}, format, err
	}
	// No rule-set format tolerates the byte order mark editors add.
	prefix = bytes.TrimPrefix(prefix, utf8BOM[:])
	if format == C.RuleSetFormatAuto {
		format = detectFormat(prefix)
	}
	return read(io.MultiReader(bytes.NewReader(prefix), reader), format)
}

func read(reader io.Reader, format string) (option.PlainRuleSet, string, error) {
	var ruleSet option.PlainRuleSet
	switch format {
	case C.RuleSetFormatSource:
		content, err := io.ReadAll(reader)
		if err != nil {
			return ruleSet, format, err
		}
		compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return ruleSet, format, err
		}
		ruleSet, err = compat.Upgrade()
		return ruleSet, format, err
	case C.RuleSetFormatBinary:
		compat, err := srs.Read(reader, false)
		if err != nil {
			return ruleSet, format, err
		}
		ruleSet, err = compat.Upgrade()
		return ruleSet, format, err
	case C.RuleSetFormatText:
		rules, err := plain.ToOptions(reader)
		ruleSet.Rules = rules
		return ruleSet, format, err
	default:
		return ruleSet, format, E.New("unknown rule-set format: ", format)
	}
}

// detectFormat recognizes a rule-set by its content, so that a path or URL is
// read the same way whether or not its name carries a matching extension.
func detectFormat(content []byte) string {
	if bytes.HasPrefix(content, srs.MagicBytes[:]) {
		return C.RuleSetFormatBinary
	}
	if meaningful := meaningfulPrefix(content); len(meaningful) > 0 && meaningful[0] == '{' {
		return C.RuleSetFormatSource
	}
	return C.RuleSetFormatText
}

// meaningfulPrefix skips the whitespace and the comments both source and text
// rule-sets may start with, leaving the first byte that identifies the format.
func meaningfulPrefix(content []byte) []byte {
	for {
		content = bytes.TrimSpace(content)
		switch {
		case bytes.HasPrefix(content, []byte("#")), bytes.HasPrefix(content, []byte("//")):
			end := bytes.IndexByte(content, '\n')
			if end < 0 {
				return nil
			}
			content = content[end+1:]
		case bytes.HasPrefix(content, []byte("/*")):
			end := bytes.Index(content[2:], []byte("*/"))
			if end < 0 {
				return content
			}
			content = content[end+4:]
		default:
			return content
		}
	}
}
