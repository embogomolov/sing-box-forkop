package plain

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/idna"
)

// ToOptions converts a plain list containing domain suffixes, IP addresses and
// CIDR prefixes into independent headless rules. Empty lines and `#` or `//`
// comments are ignored, while any other unparsable line is rejected: content
// that only looks like a list, such as an HTML error page or a rule file in
// another syntax, must not become a rule-set that silently matches nothing.
func ToOptions(reader io.Reader) ([]option.HeadlessRule, error) {
	var domains, prefixes []string
	domainSet := make(map[string]struct{})
	prefixSet := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := trimLine(scanner.Text())
		if line == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil && prefix.Addr().Zone() == "" {
			addUnique(&prefixes, prefixSet, prefix.Masked().String())
			continue
		}
		if address, err := netip.ParseAddr(line); err == nil && address.Zone() == "" {
			addUnique(&prefixes, prefixSet, address.String())
			continue
		}
		if domain, loaded := normalizeDomain(line); loaded {
			addUnique(&domains, domainSet, domain)
			continue
		}
		return nil, E.New("invalid text rule-set item: ", line)
	}
	if err := scanner.Err(); err != nil {
		return nil, E.Cause(err, "read text rule-set")
	}
	var rules []option.HeadlessRule
	if len(domains) > 0 {
		rules = append(rules, option.HeadlessRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				DomainSuffix: domains,
			},
		})
	}
	if len(prefixes) > 0 {
		rules = append(rules, option.HeadlessRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				IPCIDR: prefixes,
			},
		})
	}
	if len(rules) == 0 {
		return nil, E.New("empty text rule-set")
	}
	return rules, nil
}

func trimLine(line string) string {
	line = strings.TrimPrefix(line, "\ufeff")
	end := len(line)
	for _, marker := range []string{"#", "//"} {
		if index := strings.Index(line[:end], marker); index >= 0 {
			end = index
		}
	}
	return strings.TrimSpace(line[:end])
}

// normalizeDomain turns one list entry into a domain suffix. A `*.` or `+.`
// wildcard and a trailing root dot are notations other list formats use for the
// same suffix, so they are accepted and normalized instead of failing the list.
func normalizeDomain(value string) (string, bool) {
	value = strings.TrimSuffix(value, ".")
	var subdomainsOnly, marked bool
	switch {
	case strings.HasPrefix(value, "*."):
		value, subdomainsOnly, marked = value[2:], true, true
	case strings.HasPrefix(value, "."):
		value, subdomainsOnly, marked = value[1:], true, true
	case strings.HasPrefix(value, "+."):
		value, marked = value[2:], true
	}
	if value == "" {
		return "", false
	}
	// Only an internationalized name needs the punycode conversion, and its
	// profile rejects names an ASCII list may legitimately carry, such as the
	// underscore labels of DNS service records.
	if !asciiOnly(value) {
		converted, err := idna.Lookup.ToASCII(value)
		if err != nil {
			return "", false
		}
		value = converted
	}
	value = strings.ToLower(value)
	if !validDomain(value, marked) {
		return "", false
	}
	if subdomainsOnly {
		value = "." + value
	}
	return value, true
}

func validDomain(value string, marked bool) bool {
	if len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	// A bare name is no domain, which keeps a plain text error body from being
	// read as a one-entry rule-set; a top-level domain comes marked as a suffix,
	// as `.ua` in itdoginfo's lists.
	if len(labels) < 2 && !marked {
		return false
	}
	hasLetter := false
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			isLetter := character >= 'a' && character <= 'z'
			if isLetter {
				hasLetter = true
			}
			if !isLetter && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return hasLetter
}

func asciiOnly(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func addUnique(values *[]string, seen map[string]struct{}, value string) {
	if _, loaded := seen[value]; loaded {
		return
	}
	seen[value] = struct{}{}
	*values = append(*values, value)
}
