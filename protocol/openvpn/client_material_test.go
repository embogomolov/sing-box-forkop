//go:build with_openvpn && with_gvisor

package openvpn_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// box.New is what sing-box check runs: it builds every endpoint and starts none.
func buildBox(t *testing.T, endpoint string) error {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints": [`+endpoint+`]}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err == nil {
		require.NoError(t, instance.Close())
	}
	return err
}

func writeFile(t *testing.T, path string, content []byte) string {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func staticKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 256)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return []byte("-----BEGIN OpenVPN Static key V1-----\n" + hex.EncodeToString(key) + "\n-----END OpenVPN Static key V1-----\n")
}

func TestCheckRefusesOpenVPNClientWithMissingMaterial(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	_, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "ca.forkop.test", time.Now().Add(time.Hour))
	require.NoError(t, err)
	certificateAuthority := writeFile(t, filepath.Join(directory, "ca.crt"), certificate)
	controlKey := writeFile(t, filepath.Join(directory, "tls-crypt.key"), staticKey(t))

	staticKeyClient := func(path string) string {
		return fmt.Sprintf(`{"type": "openvpn-client", "tag": "ovpn", "server": "127.0.0.1", "server_port": 1194,
			"mode": "static_key", "static_key_path": %q, "cipher": "AES-256-CBC", "auth": "SHA256",
			"address": ["10.8.0.2/32"], "peer_address": "10.8.0.1"}`, path)
	}
	tlsClient := func(certificatePath string, controlKeyPath string) string {
		return fmt.Sprintf(`{"type": "openvpn-client", "tag": "ovpn", "server": "127.0.0.1", "server_port": 1194,
			"tls": {"certificate_path": %q, "control_wrap": {"type": "tls_crypt", "key_path": %q}}}`, certificatePath, controlKeyPath)
	}

	require.NoError(t, buildBox(t, staticKeyClient(writeFile(t, filepath.Join(directory, "static.key"), staticKey(t)))))
	require.NoError(t, buildBox(t, tlsClient(certificateAuthority, controlKey)))

	const prefix = "initialize endpoint[0] openvpn-client[ovpn]: "
	require.ErrorContains(t, buildBox(t, staticKeyClient(missing)), prefix+"load static key: open "+missing)
	require.ErrorContains(t, buildBox(t, tlsClient(missing, controlKey)), prefix+"load TLS configuration: open "+missing)
	require.ErrorContains(t, buildBox(t, tlsClient(certificateAuthority, missing)), prefix+"load control channel key: open "+missing)
}
