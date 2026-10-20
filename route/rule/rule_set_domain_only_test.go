package rule

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestDNSRuleSetDomainOnly(t *testing.T) {
	t.Parallel()
	for _, shape := range []string{"list", C.LogicalTypeOr, C.LogicalTypeAnd} {
		t.Run("domain after port-only branch "+shape, func(t *testing.T) {
			branches := []adapter.HeadlessRule{
				headlessDefaultRule(t, func(rule *abstractDefaultRule) { addDestinationPortItem(rule, []uint16{443}) }),
				headlessDefaultRule(t, func(rule *abstractDefaultRule) { addDestinationAddressItem(t, rule, nil, []string{"example.com"}) }),
			}
			if shape != "list" {
				branches = []adapter.HeadlessRule{headlessLogicalRule(shape, false, branches...)}
			}
			ruleSet := newLocalRuleSetForTest("domain-later", branches...)
			item := &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true}
			listed := testMetadata("www.example.com")
			require.True(t, item.Match(&listed))
			unlisted := testMetadata("other.test")
			require.False(t, item.Match(&unlisted))
		})
	}
	t.Run("domain with port", func(t *testing.T) {
		t.Parallel()
		metadata := testMetadata("www.example.com")
		metadata.Destination.Port = 0
		ruleSet := newLocalRuleSetForTest("dns-domain-port", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
			addDestinationAddressItem(t, rule, nil, []string{"example.com"})
			addDestinationPortItem(rule, []uint16{8443})
		}))
		rule := dnsRuleForTest(func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true})
		})
		require.True(t, rule.Match(&metadata))
		require.False(t, rule.WithAddressLimit())
	})
	t.Run("domain with ip cidr", func(t *testing.T) {
		t.Parallel()
		metadata := testMetadata("www.example.com")
		ruleSet := newLocalIPCIDRRuleSetForTest("dns-domain-ipcidr", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
			addDestinationAddressItem(t, rule, nil, []string{"example.com"})
			addDestinationIPCIDRItem(t, rule, []string{"203.0.113.0/24"})
		}))
		rule := dnsRuleForTest(func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true})
		})
		require.True(t, rule.Match(&metadata))
		require.False(t, rule.WithAddressLimit())
	})
	t.Run("domain set beside ip set", func(t *testing.T) {
		t.Parallel()
		domainSet := newLocalRuleSetForTest("dns-domains", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
			addDestinationAddressItem(t, rule, nil, []string{"example.com"})
		}))
		ipSet := newLocalIPCIDRRuleSetForTest("dns-subnets", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
			addDestinationIPCIDRItem(t, rule, []string{"203.0.113.0/24"})
		}))
		rule := dnsRuleForTest(func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{domainSet, ipSet}, domainOnly: true})
		})
		listed := testMetadata("www.example.com")
		listed.Destination.Port = 0
		require.True(t, rule.Match(&listed))
		unlisted := testMetadata("www.google.com")
		unlisted.Destination.Port = 0
		require.False(t, rule.Match(&unlisted))
		require.False(t, rule.WithAddressLimit())
	})
	t.Run("restores the context for the next rule", func(t *testing.T) {
		t.Parallel()
		ruleSet := newLocalRuleSetForTest("dns-domains", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
			addDestinationAddressItem(t, rule, nil, []string{"example.com"})
		}))
		domainRule := dnsRuleForTest(func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true})
		})
		portRule := routeRuleForTest(func(rule *abstractDefaultRule) { addDestinationPortItem(rule, []uint16{8443}) })
		cidrRule := routeRuleForTest(func(rule *abstractDefaultRule) { addDestinationIPCIDRItem(t, rule, []string{"198.51.100.0/24"}) })
		metadata := testMetadata("www.example.com")
		metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
		require.True(t, domainRule.Match(&metadata))
		require.False(t, portRule.Match(&metadata))
		require.False(t, cidrRule.Match(&metadata))
	})
	for _, testCase := range []struct {
		name           string
		containsIPCIDR bool
		build          func(*testing.T, *abstractDefaultRule)
	}{
		{
			name: "port only",
			build: func(_ *testing.T, rule *abstractDefaultRule) {
				addDestinationPortItem(rule, []uint16{443})
			},
		},
		{
			name:           "ip cidr only",
			containsIPCIDR: true,
			build: func(t *testing.T, rule *abstractDefaultRule) {
				addDestinationIPCIDRItem(t, rule, []string{"203.0.113.0/24"})
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			metadata := testMetadata("www.example.com")
			branch := headlessDefaultRule(t, func(rule *abstractDefaultRule) {
				testCase.build(t, rule)
			})
			var ruleSet adapter.RuleSet
			if testCase.containsIPCIDR {
				ruleSet = newLocalIPCIDRRuleSetForTest("dns-"+testCase.name, branch)
			} else {
				ruleSet = newLocalRuleSetForTest("dns-"+testCase.name, branch)
			}
			rule := dnsRuleForTest(func(rule *abstractDefaultRule) {
				addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true})
			})
			require.False(t, rule.Match(&metadata))
			require.False(t, rule.WithAddressLimit())
		})
	}
}

// Section rules keep the stock behaviour: an ip_cidr branch turns the rule into an
// address-limit rule that matches any domain and validates the answer afterwards.
func TestDNSRuleSetWithoutDomainOnlyKeepsAddressLimit(t *testing.T) {
	t.Parallel()
	ruleSet := newLocalIPCIDRRuleSetForTest("dns-subnets", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
		addDestinationIPCIDRItem(t, rule, []string{"203.0.113.0/24"})
	}))
	rule := dnsRuleForTest(func(rule *abstractDefaultRule) {
		addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}})
	})
	metadata := testMetadata("www.example.com")
	metadata.Destination.Port = 0
	require.True(t, rule.LegacyPreMatch(&metadata))
	require.True(t, rule.WithAddressLimit())
	rejected := metadata
	rejected.DestinationAddresses = []netip.Addr{netip.MustParseAddr("198.18.0.7")}
	require.False(t, rule.MatchAddressLimit(&rejected, dnsResponseForTest(rejected.DestinationAddresses...)))
	accepted := metadata
	accepted.DestinationAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	require.True(t, rule.MatchAddressLimit(&accepted, dnsResponseForTest(accepted.DestinationAddresses...)))
}

func newLocalIPCIDRRuleSetForTest(tag string, rules ...adapter.HeadlessRule) *LocalRuleSet {
	ruleSet := newLocalRuleSetForTest(tag, rules...)
	ruleSet.metadata = adapter.RuleSetMetadata{ContainsIPCIDRRule: true}
	return ruleSet
}
