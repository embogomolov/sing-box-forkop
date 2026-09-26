//go:build with_utls

package tls

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRealityHybridKeyShareDefaultAndLegacyOverride(t *testing.T) {
	legacy := false
	for _, test := range []struct {
		name     string
		override *bool
		want     bool
	}{
		{"default", nil, true},
		{"legacy override", &legacy, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := NewRealityClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
				Enabled: true,
				UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{
					Enabled:               true,
					PublicKey:             base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
					ShortID:               "12",
					SupportX25519MLKEM768: test.override,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := config.(*RealityClientConfig).supportX25519MLKEM768; got != test.want {
				t.Fatalf("support_x25519mlkem768 = %v, want %v", got, test.want)
			}
		})
	}
}
