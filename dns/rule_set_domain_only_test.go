package dns

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The rule-set metadata comes from the overrides, so the router is never asked.
type metadataOnlyRouter struct {
	adapter.Router
}

func ruleSetDNSRule(queryType bool, domainOnly bool) option.DNSRule {
	rule := option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				RuleSet:           badoption.Listable[string]{"domains", "subnets"},
				RuleSetDomainOnly: domainOnly,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: "fakeip"},
			},
		},
	}
	if queryType {
		rule.DefaultOptions.QueryType = badoption.Listable[option.DNSQueryType]{option.DNSQueryType(mDNS.TypeA)}
	}
	return rule
}

func TestDomainOnlyRuleTakesSubnetOnlyRuleSet(t *testing.T) {
	router := &metadataOnlyRouter{}
	metadata := map[string]adapter.RuleSetMetadata{
		"domains": {ContainsNonIPCIDRRule: true},
		"subnets": {ContainsIPCIDRRule: true},
	}

	_, err := validateLegacyDNSModeDisabledRules(router, []option.DNSRule{ruleSetDNSRule(true, false)}, metadata)
	require.Error(t, err)
	_, err = validateLegacyDNSModeDisabledRules(router, []option.DNSRule{ruleSetDNSRule(true, true)}, metadata)
	require.NoError(t, err)

	legacy, _, err := resolveLegacyDNSMode(router, []option.DNSRule{ruleSetDNSRule(false, false)}, metadata)
	require.NoError(t, err)
	require.True(t, legacy)
	legacy, _, err = resolveLegacyDNSMode(router, []option.DNSRule{ruleSetDNSRule(false, true)}, metadata)
	require.NoError(t, err)
	require.False(t, legacy)
}
