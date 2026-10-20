package raw

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/parser/subscription"
)

func TestRawSubscriptionReportsSkippedLinksWithoutTheirSecrets(t *testing.T) {
	result, err := ParseRawSubscription(context.Background(), strings.Join([]string{
		"socks5://valid.example.test:1080#valid",
		"unsupported://user:private-value@bad.example.test:443#lossy",
		"socks5://user:another-secret@hidden.example.test:1080/%zz",
		"# a comment a provider left in",
		"",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 1 || result.Outbounds[0].Tag != "valid" {
		t.Fatalf("a broken link survived or its sibling was lost: %v", result.Outbounds)
	}
	if len(result.Skipped) != 2 {
		t.Fatalf("skipped = %v", result.Skipped)
	}
	var report string
	for _, skipped := range result.Skipped {
		report += skipped.Label + ": " + skipped.Reason.Error() + "\n"
	}
	if !strings.Contains(report, "lossy") || !strings.Contains(report, "unsupported") {
		t.Fatalf("the report does not identify the links: %s", report)
	}
	for _, secret := range []string{"private-value", "bad.example.test", "another-secret", "hidden.example.test"} {
		if strings.Contains(report, secret) {
			t.Fatalf("the report leaked %q: %s", secret, report)
		}
	}
}

func TestRawSubscriptionRecognisesOnlyLinks(t *testing.T) {
	for name, content := range map[string]string{
		"prose":         "no servers here\n",
		"an empty list": "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRawSubscription(context.Background(), content); err != subscription.ErrUnrecognized {
				t.Fatalf("err = %v, want ErrUnrecognized", err)
			}
		})
	}
}
