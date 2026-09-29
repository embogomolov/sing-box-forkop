package openvpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	ovpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type userRecordingRouter struct {
	adapter.Router
	users []string
}

func (r *userRecordingRouter) PreMatch(metadata adapter.InboundContext, _ []byte) adapter.PreMatchResult {
	r.users = append(r.users, metadata.User)
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *userRecordingRouter) RouteConnectionEx(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.users = append(r.users, metadata.User)
}

func (r *userRecordingRouter) RoutePacketConnectionEx(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.users = append(r.users, metadata.User)
}

func (r *userRecordingRouter) HijackDNSPacket(_ context.Context, _ []byte, _ N.PacketWriter, metadata adapter.InboundContext) {
	r.users = append(r.users, metadata.User)
}

func testKeyPair(t *testing.T, commonName string) (certificate []byte, key []byte, fingerprint string) {
	t.Helper()
	key, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, commonName, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificate)
	sum := sha256.Sum256(block.Bytes)
	return certificate, key, hex.EncodeToString(sum[:])
}

// A client of an OpenVPN server connected over loopback, and the server
// endpoint its traffic enters the router through.
func startServerWithClient(t *testing.T, username string) (*ServerEndpoint, *userRecordingRouter, netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverCertificate, serverKey, serverFingerprint := testKeyPair(t, "server")
	clientCertificate, clientKey, clientFingerprint := testKeyPair(t, "alice")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverOptions := ovpn.ServerOptions{
		Context:   ctx,
		Mode:      ovpn.ModeTLS,
		Transport: ovpn.ServerTransportOptions{Listener: listener, Protocol: N.NetworkTCP},
		TLS: ovpn.ServerTLSOptions{
			Certificate:             ovpn.Material{Content: serverCertificate},
			Key:                     ovpn.Material{Content: serverKey},
			VerifyClientCertificate: "require",
			PeerFingerprint:         []string{clientFingerprint},
		},
		Tunnel: ovpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
			LocalAddress: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/32")},
		},
	}
	if username != "" {
		serverOptions.Authentication.Authenticator = func(_ context.Context, user string, password string) error {
			if user != username || password != "secret" {
				return ovpn.ErrAuthenticationFailed
			}
			return nil
		}
	}
	server, err := ovpn.NewServer(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	listenAddress := listener.Addr().(*net.TCPAddr)
	client, err := ovpn.NewClient(ovpn.ClientOptions{
		Context: ctx,
		Mode:    ovpn.ModeTLS,
		Transport: ovpn.ClientTransportOptions{
			Remotes:  []ovpn.Remote{{Host: "127.0.0.1", Port: uint16(listenAddress.Port), Protocol: N.NetworkTCP}},
			Protocol: N.NetworkTCP,
		},
		TLS: ovpn.ClientTLSOptions{
			Certificate:     ovpn.Material{Content: clientCertificate},
			Key:             ovpn.Material{Content: clientKey},
			PeerFingerprint: []string{serverFingerprint},
		},
		Authentication: ovpn.ClientAuthenticationOptions{Username: username, Password: "secret"},
		Pull:           ovpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	var clientAddress netip.Addr
	for deadline := time.Now().Add(10 * time.Second); !clientAddress.IsValid(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the client got no tunnel address")
		}
		if addresses := client.TunnelConfiguration().LocalIPv4; client.Ready() && len(addresses) > 0 {
			clientAddress = addresses[0].Addr()
		}
	}
	router := &userRecordingRouter{}
	return &ServerEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapter(C.TypeOpenVPNServer, "server", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			router:  router,
			logger:  log.NewNOPFactory().NewLogger("openvpn"),
		},
		ctx:            ctx,
		server:         server,
		localAddresses: serverOptions.Tunnel.LocalAddress,
	}, router, clientAddress
}

func routeClientTraffic(serverEndpoint *ServerEndpoint, source netip.Addr) {
	destination := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 443)
	serverEndpoint.JudgeFlow(uint8(header.TCPProtocolNumber), netip.AddrPortFrom(source, 40000), destination, nil)
	sourceAddress := M.SocksaddrFrom(source, 40000)
	serverEndpoint.NewConnectionEx(context.Background(), nil, sourceAddress, M.SocksaddrFromNetIP(destination), nil)
	serverEndpoint.NewPacketConnectionEx(context.Background(), nil, sourceAddress, M.SocksaddrFromNetIP(destination), nil)
	serverEndpoint.NewDNSPacket(nil, sourceAddress, M.SocksaddrFrom(netip.MustParseAddr("10.8.0.1"), 53), nil)
}

func TestServerRoutesClientTrafficAsItsUser(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		username string
		user     string
	}{
		{name: "certificate", user: "alice"},
		{name: "login", username: "bob", user: "bob"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			serverEndpoint, router, clientAddress := startServerWithClient(t, testCase.username)
			routeClientTraffic(serverEndpoint, clientAddress)
			routeClientTraffic(serverEndpoint, netip.MustParseAddr("10.8.0.200"))
			expected := []string{testCase.user, testCase.user, testCase.user, testCase.user, "", "", "", ""}
			if len(router.users) != len(expected) {
				t.Fatalf("routed %d times, expected %d", len(router.users), len(expected))
			}
			for index := range expected {
				if router.users[index] != expected[index] {
					t.Fatalf("users %q, expected %q", router.users, expected)
				}
			}
		})
	}
}
