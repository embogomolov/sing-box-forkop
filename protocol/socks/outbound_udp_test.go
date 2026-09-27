package socks

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"

	"github.com/stretchr/testify/require"
)

// Many public SOCKS5 servers answer UDP ASSOCIATE with BND.ADDR 0.0.0.0 and
// expect the client to send to the relay port on the server's own address.
func TestOutboundSendsUDPToServerWhenRelayAddressIsUnspecified(t *testing.T) {
	serverAddress := netip.MustParseAddr("127.0.0.2")
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: serverAddress.AsSlice()})
	require.NoError(t, err)
	defer relay.Close()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: serverAddress.AsSlice()})
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err = socks5.ReadAuthRequest(reader); err != nil {
			return
		}
		if err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired}); err != nil {
			return
		}
		if _, err = socks5.ReadRequest(reader); err != nil {
			return
		}
		err = socks5.WriteResponse(conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeSuccess,
			Bind:      M.Socksaddr{Addr: netip.IPv4Unspecified(), Port: uint16(relay.LocalAddr().(*net.UDPAddr).Port)},
		})
		if err != nil {
			return
		}
		_, _ = reader.ReadByte()
	}()

	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: serverAddress.String(), ServerPort: uint16(listener.Addr().(*net.TCPAddr).Port)},
	})
	require.NoError(t, err)
	packetConn, err := outbound.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.NoError(t, err)
	defer packetConn.Close()
	_, err = packetConn.WriteTo([]byte("ping"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	require.NoError(t, err)

	require.NoError(t, relay.SetReadDeadline(time.Now().Add(2*time.Second)))
	buffer := make([]byte, 64)
	n, _, err := relay.ReadFromUDP(buffer)
	require.NoError(t, err, "the relay on the server address received nothing")
	require.Contains(t, string(buffer[:n]), "ping")
}
