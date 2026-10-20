package singbox_test

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/singbox"
	"github.com/sagernet/sing-box/parser/subscription"
)

func TestParseBoxSubscriptionKeepsTheServersAndTheirChains(t *testing.T) {
	result, err := singbox.ParseBoxSubscription(include.Context(context.Background()), `{
  "outbounds": [
    null,
    {"type": "unknown", "tag": "unknown"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "socks", "tag": "broken", "server": "127.0.0.1", "server_port": 65536},
    {"type": "socks", "tag": "leaf", "server": "127.0.0.1", "server_port": 1080},
    {"type": "socks", "tag": "hop", "server": "127.0.0.1", "server_port": 1081},
    {"type": "socks", "tag": "chained", "server": "127.0.0.1", "server_port": 1082, "detour": "hop"},
    {"type": "socks", "tag": "through-direct", "server": "127.0.0.1", "server_port": 1083, "detour": "direct"},
    {"type": "socks", "tag": "external", "server": "127.0.0.1", "server_port": 1084, "detour": "global-egress"},
    {"type": "selector", "tag": "selector", "outbounds": ["leaf"]}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{"leaf", "hop", "chained", "through-direct", "external"}
	if len(result.Outbounds) != len(wantTags) {
		t.Fatalf("imported %d servers, want %d: %v", len(result.Outbounds), len(wantTags), result.Outbounds)
	}
	for index, wantTag := range wantTags {
		if result.Outbounds[index].Type != C.TypeSOCKS || result.Outbounds[index].Tag != wantTag {
			t.Errorf("server %d = %s/%s, want socks/%s", index, result.Outbounds[index].Type, result.Outbounds[index].Tag, wantTag)
		}
	}
	detours := make(map[string]string, len(result.Outbounds))
	for _, outbound := range result.Outbounds {
		detours[outbound.Tag] = outbound.Options.(*option.SOCKSOutboundOptions).Detour
	}
	// A configuration's direct outbound stands for the plain connection, so a
	// server dialling through it needs no detour; a tag the subscription never
	// defines may name an outbound of the user's own configuration.
	if detours["chained"] != "hop" || detours["through-direct"] != "" || detours["external"] != "global-egress" {
		t.Fatalf("detours = %v", detours)
	}
	if !result.Refused["broken"] || !result.Refused["block"] {
		t.Fatalf("refused = %v", result.Refused)
	}
}

func TestParseBoxSubscriptionRecognisesOnlyItsOwnFormat(t *testing.T) {
	ctx := include.Context(context.Background())
	for name, content := range map[string]string{
		"an Xray configuration": `{"outbounds": [{"protocol": "vless", "tag": "xray"}]}`,
		"missing outbounds":     `{}`,
		"wrong outbounds type":  `{"outbounds": {}}`,
		"a list of links":       "vless://uuid@example.test:443#node\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := singbox.ParseBoxSubscription(ctx, content); err != subscription.ErrUnrecognized {
				t.Fatalf("err = %v, want ErrUnrecognized", err)
			}
		})
	}
}
