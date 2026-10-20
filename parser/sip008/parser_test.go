package sip008

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
)

func TestSIP008KeepsWhatItCanAndReportsTheRestSafely(t *testing.T) {
	result, err := ParseSIP008Subscription(context.Background(), `{
  "version": 1,
  "servers": [
    {"server":"bad.example.test","server_port":8388,"password":"private-value","remarks":"lossy"},
    {"server":"valid.example.test","server_port":"8388","password":"valid-password","method":"aes-256-gcm","remarks":"valid","unsupported_option":true}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "valid" {
		t.Fatalf("the incomplete server survived or its sibling was lost: %v", result.Outbounds)
	}
	// A quoted port and a key the format does not define are both written by
	// real generators and neither changes how the server is dialled.
	options := result.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if options.ServerPort != 8388 {
		t.Fatalf("server port = %d", options.ServerPort)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("skipped = %v", result.Skipped)
	}
	report := result.Skipped[0].Label + ": " + result.Skipped[0].Reason.Error()
	if !strings.Contains(report, "lossy") {
		t.Fatalf("the report does not name the server: %s", report)
	}
	if strings.Contains(report, "private-value") || strings.Contains(report, "bad.example.test") {
		t.Fatalf("the report leaked the server's address or credentials: %s", report)
	}
}

func TestSIP008RecognisesOnlyItsOwnFormat(t *testing.T) {
	for name, content := range map[string]string{
		"a sing-box configuration": `{"outbounds": []}`,
		"a list of links":          "ss://a@example.test:443\n",
		"an array":                 `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSIP008Subscription(context.Background(), content); err != subscription.ErrUnrecognized {
				t.Fatalf("err = %v, want ErrUnrecognized", err)
			}
		})
	}
}
