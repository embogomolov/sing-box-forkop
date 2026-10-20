//go:build with_wireguard && with_gvisor

package wireguard_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func newKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(private)
	require.NoError(t, err)
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

type tunnelKeys struct {
	clientPrivate string
	serverPublic  string
	port          int
}

func (k tunnelKeys) client(tag string, extra string) string {
	return fmt.Sprintf(`{"type": "wireguard", "tag": %q, "address": ["10.77.0.2/32"], "private_key": %q%s,
		"peers": [{"address": "127.0.0.1", "port": %d, "public_key": %q, "allowed_ips": ["10.77.0.1/32"]}]}`,
		tag, k.clientPrivate, extra, k.port, k.serverPublic)
}

// startTunnelBox runs a WireGuard server endpoint and the client endpoints the
// function returns, which hold the one client key the server knows, in one box
// that logs warnings to the returned file.
func startTunnelBox(t *testing.T, clients func(tunnelKeys) []string) (*box.Box, string) {
	t.Helper()
	serverPrivate, serverPublic := newKeyPair(t)
	clientPrivate, clientPublic := newKeyPair(t)
	keys := tunnelKeys{clientPrivate: clientPrivate, serverPublic: serverPublic, port: freeUDPPort(t)}
	logPath := filepath.Join(t.TempDir(), "box.log")
	endpoints := append([]string{fmt.Sprintf(`{"type": "wireguard", "tag": "server", "address": ["10.77.0.1/32"], "private_key": %q,
		"listen_port": %d, "peers": [{"public_key": %q, "allowed_ips": ["10.77.0.2/32"]}]}`, serverPrivate, keys.port, clientPublic)},
		clients(keys)...)
	content := fmt.Sprintf(`{
		"log": {"level": "warn", "output": %q},
		"endpoints": [%s],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"final": "direct"}
	}`, logPath, strings.Join(endpoints, ","))
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	return instance, logPath
}

func startEchoListener(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("ok"))
			conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func dialThrough(t *testing.T, instance *box.Box, tag string, port int) error {
	t.Helper()
	endpoint, loaded := instance.Endpoint().Get(tag)
	require.True(t, loaded, tag)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := endpoint.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("10.77.0.1", uint16(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if string(reply) != "ok" {
		return fmt.Errorf("read %q", reply)
	}
	return nil
}

func sharesDevice(t *testing.T, instance *box.Box, a, b string) bool {
	t.Helper()
	first, loaded := instance.Endpoint().Get(a)
	require.True(t, loaded, a)
	second, loaded := instance.Endpoint().Get(b)
	require.True(t, loaded, b)
	return wireguard.SharesDevice(first, second)
}

func twoIdenticalClients(keys tunnelKeys) []string {
	return []string{keys.client("client-a", ""), keys.client("client-b", "")}
}

// A WireGuard server keeps one session and one address per client key and
// refuses a second handshake right after the first as a flood, so two devices
// holding one key could not both carry traffic.
func TestIdenticalEndpointsShareOneTunnel(t *testing.T) {
	port := startEchoListener(t)
	instance, _ := startTunnelBox(t, twoIdenticalClients)
	for i, tag := range []string{"client-a", "client-b", "client-a", "client-b"} {
		require.NoError(t, dialThrough(t, instance, tag, port), "dial %d through %s", i, tag)
	}
	require.True(t, sharesDevice(t, instance, "client-a", "client-b"))
	for _, tag := range []string{"client-a", "client-b"} {
		endpoint, _ := instance.Endpoint().Get(tag)
		require.Equal(t, "wireguard", endpoint.Type())
		require.Equal(t, tag, endpoint.Tag())
	}
}

func TestSharedTunnelOutlivesTheEndpointThatCreatedIt(t *testing.T) {
	port := startEchoListener(t)
	instance, _ := startTunnelBox(t, twoIdenticalClients)
	require.NoError(t, dialThrough(t, instance, "client-a", port))
	creator, loaded := instance.Endpoint().Get("client-a")
	require.True(t, loaded)
	require.NoError(t, wireguard.ReleaseDevice(creator))
	require.NoError(t, dialThrough(t, instance, "client-b", port))
}

// Endpoints that hold one key for one server with other settings cannot share
// a device and cannot coexist either, which the log has to say.
func TestSameKeyWithOtherSettingsIsReported(t *testing.T) {
	instance, logPath := startTunnelBox(t, func(keys tunnelKeys) []string {
		return []string{keys.client("client-a", ""), keys.client("client-b", `, "mtu": 1280`)}
	})
	require.False(t, sharesDevice(t, instance, "client-a", "client-b"))
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(content), "holds the same WireGuard key for the same peer"), string(content))
	require.Contains(t, string(content), "endpoint/wireguard[client-b]: endpoint[client-a]")
}

// One client key may serve several servers: those are separate peers, each
// with its own session.
func TestSameKeyForAnotherServerIsNotAConflict(t *testing.T) {
	_, otherServer := newKeyPair(t)
	instance, logPath := startTunnelBox(t, func(keys tunnelKeys) []string {
		other := keys
		other.serverPublic = otherServer
		return []string{keys.client("client-a", ""), other.client("client-b", "")}
	})
	require.False(t, sharesDevice(t, instance, "client-a", "client-b"))
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotContains(t, string(content), "holds the same WireGuard key")
}
