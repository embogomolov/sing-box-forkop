package link

import (
	"encoding/base64"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/protobuf/proto"
)

func parseMieruLink(link string) (option.Outbound, error) {
	link, tag, err := splitMieruLinkFragment(link)
	if err != nil {
		return option.Outbound{}, err
	}
	config, err := parseMieruClientConfig(link)
	if err != nil {
		return option.Outbound{}, err
	}
	profile, err := selectMieruProfile(config)
	if err != nil {
		return option.Outbound{}, err
	}
	options, err := mieruProfileToOutboundOptions(profile)
	if err != nil {
		return option.Outbound{}, err
	}
	return option.Outbound{
		Type:    C.TypeMieru,
		Tag:     tag,
		Options: options,
	}, nil
}

func splitMieruLinkFragment(link string) (string, string, error) {
	link, fragment, found := strings.Cut(link, "#")
	if !found {
		return link, "", nil
	}
	tag, err := url.PathUnescape(fragment)
	if err != nil {
		return "", "", E.Cause(err, "decode fragment")
	}
	return link, tag, nil
}

// The two link forms of mieru's own client: mieru:// carries a whole client
// configuration as base64 of its protobuf, mierus:// one profile in URL fields.
func parseMieruClientConfig(link string) (*mierupb.ClientConfig, error) {
	if encoded, found := strings.CutPrefix(link, "mieru://"); found {
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, E.Cause(err, "decode mieru link")
		}
		config := &mierupb.ClientConfig{}
		if err = proto.Unmarshal(content, config); err != nil {
			return nil, E.Cause(err, "decode mieru link")
		}
		return config, nil
	}
	profile, err := parseMieruSimpleLink(link)
	if err != nil {
		return nil, err
	}
	return &mierupb.ClientConfig{Profiles: []*mierupb.ClientProfile{profile}}, nil
}

func parseMieruSimpleLink(link string) (*mierupb.ClientProfile, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return nil, E.Cause(err, "parse mieru link")
	}
	if linkURL.Scheme != "mierus" {
		return nil, E.New("unrecognized mieru link scheme: ", linkURL.Scheme)
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return nil, E.New("mieru link has no user name")
	}
	password, _ := linkURL.User.Password()
	if password == "" {
		return nil, E.New("mieru link has no password")
	}
	if linkURL.Hostname() == "" {
		return nil, E.New("mieru link has no host")
	}
	query, err := url.ParseQuery(linkURL.RawQuery)
	if err != nil {
		return nil, E.Cause(err, "parse mieru link query")
	}
	if query.Get("profile") == "" {
		return nil, E.New("mieru link has no profile name")
	}
	profile := &mierupb.ClientProfile{
		ProfileName: proto.String(query.Get("profile")),
		User:        &mierupb.User{Name: proto.String(linkURL.User.Username()), Password: proto.String(password)},
	}
	if value := query.Get("mtu"); value != "" {
		mtu, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return nil, E.New("invalid mieru MTU: ", value)
		}
		profile.Mtu = proto.Int32(int32(mtu))
	}
	if value := query.Get("multiplexing"); value != "" {
		level := mierupb.MultiplexingLevel(mierupb.MultiplexingLevel_value[value])
		profile.Multiplexing = &mierupb.MultiplexingConfig{Level: &level}
	}
	if value := query.Get("handshake-mode"); value != "" {
		profile.HandshakeMode = mierupb.HandshakeMode(mierupb.HandshakeMode_value[value]).Enum()
	}
	if value := query.Get("traffic-pattern"); value != "" {
		content, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, E.Cause(err, "decode mieru traffic pattern")
		}
		profile.TrafficPattern = &mierupb.TrafficPattern{}
		if err = proto.Unmarshal(content, profile.TrafficPattern); err != nil {
			return nil, E.Cause(err, "decode mieru traffic pattern")
		}
	}
	server := &mierupb.ServerEndpoint{}
	if _, err = netip.ParseAddr(linkURL.Hostname()); err == nil {
		server.IpAddress = proto.String(linkURL.Hostname())
	} else {
		server.DomainName = proto.String(linkURL.Hostname())
	}
	ports, protocols := query["port"], query["protocol"]
	if len(ports) != len(protocols) {
		return nil, E.New("mieru link has ", len(ports), " ports and ", len(protocols), " protocols")
	}
	for i, port := range ports {
		binding := &mierupb.PortBinding{
			Protocol: mierupb.TransportProtocol(mierupb.TransportProtocol_value[protocols[i]]).Enum(),
		}
		if begin, end, isRange := strings.Cut(port, "-"); isRange {
			beginPort, beginErr := strconv.ParseUint(begin, 10, 16)
			endPort, endErr := strconv.ParseUint(end, 10, 16)
			if beginErr != nil || endErr != nil || beginPort == 0 || beginPort > endPort {
				return nil, E.New("invalid mieru port range: ", port)
			}
			binding.PortRange = proto.String(strconv.FormatUint(beginPort, 10) + "-" + strconv.FormatUint(endPort, 10))
		} else {
			portNumber, err := strconv.ParseUint(port, 10, 16)
			if err != nil || portNumber == 0 {
				return nil, E.New("invalid mieru port: ", port)
			}
			binding.Port = proto.Int32(int32(portNumber))
		}
		server.PortBindings = append(server.PortBindings, binding)
	}
	profile.Servers = []*mierupb.ServerEndpoint{server}
	return profile, nil
}

func selectMieruProfile(config *mierupb.ClientConfig) (*mierupb.ClientProfile, error) {
	profiles := config.GetProfiles()
	if activeProfile := config.GetActiveProfile(); activeProfile != "" {
		for _, profile := range profiles {
			if profile.GetProfileName() == activeProfile {
				return profile, nil
			}
		}
		return nil, E.New("active mieru profile not found: ", activeProfile)
	}
	if len(profiles) != 1 {
		return nil, E.New("mieru link must contain exactly one profile without active_profile")
	}
	return profiles[0], nil
}
func mieruProfileToOutboundOptions(profile *mierupb.ClientProfile) (*option.MieruOutboundOptions, error) {
	if len(profile.GetServers()) != 1 {
		return nil, E.New("mieru profile must contain exactly one server")
	}
	if profile.GetMtu() < 0 || profile.GetMtu() > 65535 {
		return nil, E.New("invalid mieru MTU: ", profile.GetMtu())
	}
	if _, ok := mierupb.HandshakeMode_name[int32(profile.GetHandshakeMode())]; !ok {
		return nil, E.New("unsupported mieru handshake mode: ", profile.GetHandshakeMode())
	}
	server := profile.GetServers()[0]
	serverAddress := server.GetDomainName()
	if serverAddress == "" {
		serverAddress = server.GetIpAddress()
	}
	if serverAddress == "" {
		return nil, E.New("mieru server address is empty")
	}
	user := profile.GetUser()
	if user.GetName() == "" || user.GetPassword() == "" {
		return nil, E.New("mieru username and password are required")
	}
	bindings := server.GetPortBindings()
	if len(bindings) == 0 {
		return nil, E.New("mieru server has no port bindings")
	}
	transport := bindings[0].GetProtocol().String()
	if transport != "TCP" && transport != "UDP" {
		return nil, E.New("invalid mieru transport: ", transport)
	}
	options := &option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: serverAddress},
		Transport:     transport,
		UserName:      user.GetName(),
		Password:      user.GetPassword(),
		MTU:           uint32(profile.GetMtu()),
	}
	if profile.HandshakeMode != nil {
		options.HandshakeMode = profile.GetHandshakeMode().String()
	}
	if profile.Multiplexing != nil && profile.GetMultiplexing().GetLevel() != mierupb.MultiplexingLevel_MULTIPLEXING_DEFAULT {
		options.Multiplexing = profile.GetMultiplexing().GetLevel().String()
	}
	if trafficPattern := profile.GetTrafficPattern(); trafficPattern != nil {
		content, err := proto.Marshal(trafficPattern)
		if err != nil {
			return nil, E.Cause(err, "marshal mieru traffic pattern")
		}
		options.TrafficPattern = base64.StdEncoding.EncodeToString(content)
	}
	for _, binding := range bindings {
		if binding.GetProtocol().String() != transport {
			return nil, E.New("mixed mieru transports cannot be represented by one outbound")
		}
		if portRange := binding.GetPortRange(); portRange != "" {
			options.ServerPortRanges = append(options.ServerPortRanges, portRange)
			continue
		}
		port := binding.GetPort()
		if port < 1 || port > 65535 {
			return nil, E.New("invalid mieru server port: ", port)
		}
		if options.ServerPort == 0 {
			options.ServerPort = uint16(port)
		} else {
			options.ServerPortRanges = append(options.ServerPortRanges, strconv.Itoa(int(port))+"-"+strconv.Itoa(int(port)))
		}
	}
	return options, nil
}
