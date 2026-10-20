//go:build with_mieru

package link

import (
	"testing"

	mieruappctl "github.com/enfein/mieru/v3/pkg/appctl"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/protobuf/proto"
)

func TestParseMieruSimpleLink(t *testing.T) {
	outbound, err := ParseSubscriptionLink("mierus://alice:s3cret@203.0.113.7?profile=default&port=2012-2022&protocol=TCP&multiplexing=MULTIPLEXING_HIGH#Mieru")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.MieruOutboundOptions)
	if outbound.Type != C.TypeMieru || outbound.Tag != "Mieru" {
		t.Fatalf("unexpected outbound: type=%q tag=%q", outbound.Type, outbound.Tag)
	}
	if options.Server != "203.0.113.7" || options.UserName != "alice" || options.Password != "s3cret" || options.Transport != "TCP" {
		t.Fatalf("unexpected mieru options: %#v", options)
	}
	if len(options.ServerPortRanges) != 1 || options.ServerPortRanges[0] != "2012-2022" || options.Multiplexing != "MULTIPLEXING_HIGH" {
		t.Fatalf("unexpected mieru port options: %#v", options)
	}
}

func TestParseMieruStandardLink(t *testing.T) {
	link, err := mieruappctl.ClientConfigToURL(&mierupb.ClientConfig{
		Profiles: []*mierupb.ClientProfile{{
			ProfileName:   proto.String("default"),
			Mtu:           proto.Int32(1280),
			HandshakeMode: mierupb.HandshakeMode_HANDSHAKE_NO_WAIT.Enum(),
			User:          &mierupb.User{Name: proto.String("alice"), Password: proto.String("s3cret")},
			Servers: []*mierupb.ServerEndpoint{{
				DomainName: proto.String("mieru.example"),
				PortBindings: []*mierupb.PortBinding{{
					Port: proto.Int32(443), Protocol: mierupb.TransportProtocol_TCP.Enum(),
				}},
			}},
		}},
		ActiveProfile: proto.String("default"),
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := ParseSubscriptionLink(link)
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.MieruOutboundOptions)
	if outbound.Type != C.TypeMieru || options.Server != "mieru.example" || options.ServerPort != 443 || options.Transport != "TCP" || options.MTU != 1280 || options.HandshakeMode != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("unexpected mieru options: %#v", options)
	}
}

func TestParseMieruLinksAsMieruReadsThem(t *testing.T) {
	tcp, udp := mierupb.TransportProtocol_TCP.Enum(), mierupb.TransportProtocol_UDP.Enum()
	level := mierupb.MultiplexingLevel_MULTIPLEXING_HIGH
	profiles := []*mierupb.ClientProfile{{
		ProfileName: proto.String("plain"),
		User:        &mierupb.User{Name: proto.String("alice"), Password: proto.String("s3cret")},
		Servers: []*mierupb.ServerEndpoint{{
			DomainName:   proto.String("mieru.example"),
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(443), Protocol: tcp}},
		}},
	}, {
		ProfileName:   proto.String("every field"),
		User:          &mierupb.User{Name: proto.String("b@b:/?#"), Password: proto.String("p&s=s+w%d")},
		Mtu:           proto.Int32(1400),
		Multiplexing:  &mierupb.MultiplexingConfig{Level: &level},
		HandshakeMode: mierupb.HandshakeMode_HANDSHAKE_NO_WAIT.Enum(),
		TrafficPattern: &mierupb.TrafficPattern{
			Seed:        proto.Int32(7),
			UnlockAll:   proto.Bool(true),
			TcpFragment: &mierupb.TCPFragment{Enable: proto.Bool(true), MaxSleepMs: proto.Int32(10)},
		},
		Servers: []*mierupb.ServerEndpoint{{
			IpAddress: proto.String("203.0.113.7"),
			PortBindings: []*mierupb.PortBinding{
				{PortRange: proto.String("2012-2022"), Protocol: udp},
				{Port: proto.Int32(2030), Protocol: udp},
			},
		}, {
			IpAddress:    proto.String("2001:db8::7"),
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(8964), Protocol: tcp}},
		}},
	}}
	var links []string
	for _, profile := range profiles {
		profileLinks, err := mieruappctl.ClientProfileToMultiURLs(profile)
		if err != nil {
			t.Fatal(err)
		}
		links = append(links, profileLinks...)
	}
	configLink, err := mieruappctl.ClientConfigToURL(&mierupb.ClientConfig{Profiles: profiles, ActiveProfile: proto.String("every field")})
	if err != nil {
		t.Fatal(err)
	}
	links = append(links, configLink,
		"mierus://alice@mieru.example?profile=p&port=443&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?port=443&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&port=443",
		"mierus://alice:s3cret@mieru.example?profile=p&port=0&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&port=65536&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&port=2022-2012&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&port=1-2-3&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&mtu=x&port=443&protocol=TCP",
		"mierus://alice:s3cret@mieru.example?profile=p&traffic-pattern=%25&port=443&protocol=TCP",
		"mieru://not base64",
	)
	for _, link := range links {
		want, wantErr := mieruappctl.ParseURLClientConfig(link)
		got, err := parseMieruClientConfig(link)
		if (err == nil) != (wantErr == nil) {
			t.Fatalf("%s: got error %v, mieru got %v", link, err, wantErr)
		}
		if !proto.Equal(got, want) {
			t.Fatalf("%s:\ngot   %v\nmieru %v", link, got, want)
		}
	}
}

func TestGenerateMieruLinkRoundTrip(t *testing.T) {
	testLinkRoundTrip(t, option.Outbound{
		Type: C.TypeMieru,
		Tag:  "Mieru node",
		Options: &option.MieruOutboundOptions{
			ServerOptions:    option.ServerOptions{Server: "mieru.example", ServerPort: 31434},
			ServerPortRanges: []string{"40000-40010"},
			Transport:        "TCP",
			UserName:         "mieru-user", Password: "mieru-secret",
		},
	})
}
