package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func TestRuleSetMatchDoesNotCopyMetadata(t *testing.T) {
	ruleSet := newLocalRuleSetForTest("alloc",
		headlessDefaultRule(t, func(rule *abstractDefaultRule) { addDestinationPortItem(rule, []uint16{8443}) }),
		headlessLogicalRule(C.LogicalTypeOr, false,
			headlessDefaultRule(t, func(rule *abstractDefaultRule) { addDestinationIPCIDRItem(t, rule, []string{"203.0.113.0/24"}) }),
			headlessDefaultRule(t, func(rule *abstractDefaultRule) { addDestinationKeywordItem(rule, []string{"example"}) }),
		),
	)
	for _, testCase := range []struct {
		name string
		rule adapter.Rule
	}{
		{
			name: "route",
			rule: routeRuleForTest(func(rule *abstractDefaultRule) {
				addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}})
			}),
		},
		{
			name: "dns domain only",
			rule: dnsRuleForTest(func(rule *abstractDefaultRule) {
				addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, domainOnly: true})
			}),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := testMetadata("www.example.com")
			allocs := testing.AllocsPerRun(100, func() {
				if !testCase.rule.Match(&metadata) {
					t.Fatal("rule-set did not match")
				}
			})
			if allocs != 0 {
				t.Fatalf("rule-set match allocated %v times", allocs)
			}
		})
	}
}
