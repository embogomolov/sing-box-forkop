//go:build with_wireguard && with_gvisor

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// A reload runs this binary again to check the configuration; the test binary
// stands in for it when the variable is set.
func TestMain(m *testing.M) {
	if os.Getenv("SING_BOX_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func writeReloadConfig(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	t.Setenv("SING_BOX_TEST_MAIN", "1")
	previous := configPaths
	configPaths = []string{path}
	t.Cleanup(func() { configPaths = previous })
	preRun(mainCommand, nil)
}

func publicKey(t *testing.T) string {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(private)
	require.NoError(t, err)
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(public)
}

// A WireGuard endpoint starts its netstack while it is built, and closing the unstarted box never
// stops it.
func TestReloadCheckLeavesNothingRunning(t *testing.T) {
	writeReloadConfig(t, fmt.Sprintf(`{
		"log": {"level": "error"},
		"endpoints": [{"type": "wireguard", "tag": "wg", "address": ["10.77.0.2/32"], "private_key": %q,
			"peers": [{"address": "127.0.0.1", "port": 51820, "public_key": %q, "allowed_ips": ["0.0.0.0/0"]}]}]
	}`, publicKey(t), publicKey(t)))
	before := runtime.NumGoroutine()
	require.NoError(t, checkForReload())
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), before)
}

func TestReloadCheckReportsTheCause(t *testing.T) {
	writeReloadConfig(t, `{"outbounds": [{"type": "no-such-type", "tag": "x"}]}`)
	err := checkForReload()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no-such-type")
	require.NotContains(t, err.Error(), "FATAL")
}
