package subscription

import (
	"encoding/base64"
	"strings"
)

// DecodeBase64 decodes the base64 a subscription may be wrapped in: standard or URL-safe, padded
// or not, with line breaks, and with plus signs a query string turned into spaces. It reports
// whether the content was base64, so a caller can tell a wrapped subscription from a plain one.
func DecodeBase64(content string) (string, bool) {
	stripped := strings.NewReplacer("\r", "", "\n", "", "\t", "").Replace(strings.TrimSpace(content))
	stripped = strings.TrimRight(stripped, "=")
	if stripped == "" {
		return "", false
	}
	for _, candidate := range []struct {
		encoding *base64.Encoding
		content  string
	}{
		{base64.RawStdEncoding, stripped},
		{base64.RawURLEncoding, stripped},
		{base64.RawStdEncoding, strings.ReplaceAll(stripped, " ", "+")},
		{base64.RawURLEncoding, strings.ReplaceAll(stripped, " ", "-")},
	} {
		if decoded, err := candidate.encoding.DecodeString(candidate.content); err == nil {
			return string(decoded), true
		}
	}
	return "", false
}
