//go:build with_utls

package tls

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestRealityRejectsShortIDLongerThanEightBytes(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		shortID string
		valid   bool
	}{
		{"0123456789abcdef", true},
		{"0123456789abcdef01", false},
		{"0123456789abcdef0123", false},
	} {
		t.Run(test.shortID, func(t *testing.T) {
			_, clientErr := NewRealityClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
				Enabled: true,
				UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: key, ShortID: test.shortID},
			})
			if test.valid {
				require.NoError(t, clientErr)
				return
			}
			require.ErrorContains(t, clientErr, "invalid short_id")
			_, serverErr := NewRealityServer(context.Background(), nil, option.InboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
				Reality: &option.InboundRealityOptions{
					Enabled:    true,
					PrivateKey: key,
					ShortID:    []string{test.shortID},
					Handshake:  option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443}},
				},
			})
			require.ErrorContains(t, serverErr, "invalid short_id")
		})
	}
}
