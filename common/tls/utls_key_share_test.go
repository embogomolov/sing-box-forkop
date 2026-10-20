//go:build with_utls

package tls

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func buildClientHello(t *testing.T, fingerprint string) *utls.UConn {
	t.Helper()
	id, err := uTLSClientHelloID(fingerprint)
	require.NoError(t, err)
	uConn, err := newUClient(&net.TCPConn{}, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, id)
	require.NoError(t, err)
	require.NoError(t, uConn.BuildHandshakeState())
	return uConn
}

func clientHelloKeyShares(t *testing.T, uConn *utls.UConn) []utls.KeyShare {
	t.Helper()
	for _, extension := range uConn.Extensions {
		if keyShare, isKeyShare := extension.(*utls.KeyShareExtension); isKeyShare {
			return keyShare.KeyShares
		}
	}
	t.Fatal("no key_share extension")
	return nil
}

func keyShareIndex(shares []utls.KeyShare, group utls.CurveID) (index int, count int) {
	index = -1
	for i, share := range shares {
		if share.Group == group {
			if index == -1 {
				index = i
			}
			count++
		}
	}
	return
}

// Xray REALITY since v26.9.8 accepts a ClientHello only with one X25519MLKEM768
// key share ahead of one X25519 share and answers anything else with its
// camouflage site.
func TestFingerprintsCarryOneHybridKeyShareFirst(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "firefox", "safari"} {
		t.Run(fingerprint, func(t *testing.T) {
			shares := clientHelloKeyShares(t, buildClientHello(t, fingerprint))
			hybrid, hybridCount := keyShareIndex(shares, utls.X25519MLKEM768)
			classical, classicalCount := keyShareIndex(shares, utls.X25519)
			require.Equal(t, 1, hybridCount, "X25519MLKEM768 key shares")
			require.Equal(t, 1, classicalCount, "X25519 key shares")
			require.Less(t, hybrid, classical, "X25519MLKEM768 must precede X25519")
			require.Len(t, shares[hybrid].Data, 1184+32)
			require.Len(t, shares[classical].Data, 32)
		})
	}
}

// REALITY derives its auth key from KeyShareKeys.Ecdhe, so the X25519 half of
// the hybrid share has to be that same key, as Firefox sends it.
func TestFirefoxHybridKeyShareReusesTheX25519Key(t *testing.T) {
	uConn := buildClientHello(t, "firefox")
	shares := clientHelloKeyShares(t, uConn)
	hybrid, _ := keyShareIndex(shares, utls.X25519MLKEM768)
	classical, _ := keyShareIndex(shares, utls.X25519)
	require.NotEqual(t, -1, hybrid)
	require.NotEqual(t, -1, classical)
	require.Equal(t, shares[classical].Data, shares[hybrid].Data[len(shares[hybrid].Data)-32:])
	keys := uConn.HandshakeState.State13.KeyShareKeys
	require.NotNil(t, keys)
	require.Same(t, keys.Ecdhe, keys.MlkemEcdhe)
	require.Equal(t, shares[classical].Data, keys.Ecdhe.PublicKey().Bytes())
}
