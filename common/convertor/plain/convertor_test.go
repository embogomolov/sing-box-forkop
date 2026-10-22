package plain

import (
	"slices"
	"strings"
	"testing"
)

func TestToOptionsMixedList(t *testing.T) {
	rules, err := ToOptions(strings.NewReader("\ufeff# comment\r\n" +
		"Example.COM\r\n" +
		".Sub.Example.COM // suffix comment\r\n" +
		"*.Wildcard.Example.COM\r\n" +
		"+.Apex.Example.COM\r\n" +
		"fqdn.example.com.\r\n" +
		"_dmarc.example.com\r\n" +
		"пример.рф\r\n" +
		"192.0.2.1\r\n" +
		"198.51.100.23/24 # prefix comment\r\n" +
		"2001:db8::1\r\n" +
		"Example.COM\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected domain and IP rules, got %d", len(rules))
	}
	wantDomains := []string{
		"example.com",
		".sub.example.com",
		".wildcard.example.com",
		"apex.example.com",
		"fqdn.example.com",
		"_dmarc.example.com",
		"xn--e1afmkfd.xn--p1ai",
	}
	if !slices.Equal(rules[0].DefaultOptions.DomainSuffix, wantDomains) {
		t.Fatalf("unexpected domains: %v", rules[0].DefaultOptions.DomainSuffix)
	}
	wantPrefixes := []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1"}
	if !slices.Equal(rules[1].DefaultOptions.IPCIDR, wantPrefixes) {
		t.Fatalf("unexpected prefixes: %v", rules[1].DefaultOptions.IPCIDR)
	}
}

func TestToOptionsTopLevelSuffixes(t *testing.T) {
	rules, err := ToOptions(strings.NewReader(".ua\n*.UA\n+.рф\nexample.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantDomains := []string{".ua", "xn--p1ai", "example.com"}
	if !slices.Equal(rules[0].DefaultOptions.DomainSuffix, wantDomains) {
		t.Fatalf("unexpected domains: %v", rules[0].DefaultOptions.DomainSuffix)
	}
}

func TestToOptionsRejectsForeignSyntax(t *testing.T) {
	for name, content := range map[string]string{
		"html":          "<html><body>denied</body></html>\n",
		"hosts":         "0.0.0.0 ads.example.com\n",
		"adblock":       "[Adblock Plus 2.0]\n||ads.example.com^\n",
		"clash":         "DOMAIN-SUFFIX,example.com\n",
		"yaml":          "payload:\n  - example.com\n",
		"url":           "https://example.com/list\n",
		"host-and-port": "example.com:443\n",
		"bare-name":     "Forbidden\n",
		"invalid-ip":    "999.999.999.999\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ToOptions(strings.NewReader(content)); err == nil {
				t.Fatal("expected an invalid item error")
			}
		})
	}
}

func TestToOptionsRejectsEmptyList(t *testing.T) {
	_, err := ToOptions(strings.NewReader("# comment\n\n// another comment\n"))
	if err == nil {
		t.Fatal("expected an empty text rule-set error")
	}
}
