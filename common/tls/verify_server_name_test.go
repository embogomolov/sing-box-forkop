//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A server whose certificate is valid for another name than the client sends, as the links
// of Xray-core's panels describe with vcn: verify_server_name accepts it by those names and
// still verifies the chain.
func TestVerifyServerName(t *testing.T) {
	trusted, isTrusted := trustedServerCertificate()
	if !isTrusted {
		if runtime.GOOS == "linux" {
			t.Fatal("the system roots of this process cannot be set: were they loaded by an earlier test?")
		}
		t.Skip("the system roots of this process cannot be set")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	untrusted := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	for _, testCase := range []struct {
		name        string
		certificate tls.Certificate
		names       []string
		disableSNI  bool
		insecure    bool
		err         string
	}{
		{"server name only", trusted, nil, false, false, "x509: certificate is valid for example.org, not front.example.com"},
		{"one name", trusted, []string{"example.org"}, false, false, ""},
		{"any of the names", trusted, []string{"other.example.org", "EXAMPLE.org"}, false, false, ""},
		{"no name matches", trusted, []string{"other.example.org"}, false, false, "x509: certificate is valid for example.org, not other.example.org"},
		{"without SNI", trusted, []string{"example.org"}, true, false, ""},
		{"untrusted chain", untrusted, []string{"example.org"}, false, false, "x509: certificate signed by unknown authority"},
		{"insecure", untrusted, []string{"other.example.org"}, false, true, ""},
	} {
		for _, engine := range []string{"std", "utls"} {
			t.Run(testCase.name+" "+engine, func(t *testing.T) {
				options := option.OutboundTLSOptions{
					Enabled:          true,
					ServerName:       "front.example.com",
					DisableSNI:       testCase.disableSNI,
					Insecure:         testCase.insecure,
					VerifyServerName: badoption.Listable[string](testCase.names),
				}
				if engine == "utls" {
					options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
				}
				logger, _ := newWarnLogger(t)
				config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
				require.NoError(t, err)
				// a socket, not a pipe: a refused handshake crosses the client's alert with
				// the rest of the server's flight
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()
				client, err := net.Dial("tcp", listener.Addr().String())
				require.NoError(t, err)
				defer client.Close()
				server, err := listener.Accept()
				require.NoError(t, err)
				plainTLSServer(t, server, testCase.certificate)

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				conn, err := ClientHandshake(ctx, client, config.Clone())
				if testCase.err != "" {
					require.ErrorContains(t, err, testCase.err)
					return
				}
				require.NoError(t, err)
				conn.Close()
			})
		}
	}
}

func TestVerifyServerNameConflictsWithPublicKeyPin(t *testing.T) {
	logger, _ := newWarnLogger(t)
	_, err := NewClient(context.Background(), logger, "example.org", option.OutboundTLSOptions{
		Enabled:                    true,
		CertificatePublicKeySHA256: badoption.Listable[[]byte]{make([]byte, 32)},
		VerifyServerName:           badoption.Listable[string]{"example.org"},
	})
	require.ErrorContains(t, err, "verify_server_name is conflict with certificate_public_key_sha256")
}
