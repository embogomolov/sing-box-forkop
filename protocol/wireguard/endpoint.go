package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardEndpointOptions](registry, C.TypeWireGuard, NewEndpoint)
	endpoint.Register[option.AmneziaWGEndpointOptions](registry, C.TypeAmneziaWG, NewAmneziaWGEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx            context.Context
	router         adapter.Router
	dnsRouter      adapter.DNSRouter
	logger         logger.ContextLogger
	localAddresses []netip.Prefix
	endpoint       *wireguard.Endpoint
	device         *sharedDevice
	started        atomic.Bool
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
	return newEndpoint(ctx, router, logger, C.TypeWireGuard, tag, options.WireGuardCommonOptions, oneSidedAmneziaOptions(options.Amnezia))
}

func NewAmneziaWGEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AmneziaWGEndpointOptions) (adapter.Endpoint, error) {
	return newEndpoint(ctx, router, logger, C.TypeAmneziaWG, tag, options.WireGuardCommonOptions, amneziaOptions(options.Amnezia))
}

// oneSidedAmneziaOptions maps the obfuscation a peer never has to know about.
func oneSidedAmneziaOptions(options *option.OneSidedAmnezia) *wireguard.AmneziaOptions {
	if options == nil {
		return nil
	}
	return &wireguard.AmneziaOptions{
		JC:                     options.JC,
		JMin:                   options.JMin,
		JMax:                   options.JMax,
		I1:                     options.I1,
		I2:                     options.I2,
		I3:                     options.I3,
		I4:                     options.I4,
		I5:                     options.I5,
		ContentPaddingAddition: options.ContentPaddingAddition,
		RekeyAfterTime:         options.RekeyAfterTime,
		RekeyTimeout:           options.RekeyTimeout,
		RejectAfterTime:        options.RejectAfterTime,
		KeepaliveTimeout:       options.KeepaliveTimeout,
		MaxHandshakeAttempts:   options.MaxHandshakeAttempts,
		DisableCookies:         options.DisableCookies,
	}
}

// amneziaOptions adds the parameters that only match a peer speaking AmneziaWG.
func amneziaOptions(options *option.WireGuardAmnezia) *wireguard.AmneziaOptions {
	if options == nil {
		return nil
	}
	amnezia := oneSidedAmneziaOptions(&options.OneSidedAmnezia)
	amnezia.S1 = options.S1
	amnezia.S2 = options.S2
	amnezia.S3 = options.S3
	amnezia.S4 = options.S4
	amnezia.H1 = options.H1
	amnezia.H2 = options.H2
	amnezia.H3 = options.H3
	amnezia.H4 = options.H4
	amnezia.HeaderProtectionKey = options.HeaderProtectionKey
	amnezia.RandomTrailers = options.RandomTrailers
	return amnezia
}

func newEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, endpointType string, tag string, options option.WireGuardCommonOptions, amnezia *wireguard.AmneziaOptions) (adapter.Endpoint, error) {
	options.UDPFragmentDefault = true
	ep := &Endpoint{
		Adapter:        endpoint.NewAdapterWithDialerOptions(endpointType, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:            ctx,
		router:         router,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		logger:         logger,
		localAddresses: options.Address,
	}
	if options.Detour != "" && options.ListenPort != 0 {
		return nil, E.New("`listen_port` is conflict with `detour`")
	}
	configuration, identities, err := sharedDeviceKey(endpointType, options, amnezia)
	if err != nil {
		return nil, err
	}
	registry := deviceRegistryFromContext(ctx)
	if registry != nil {
		registry.access.Lock()
		defer registry.access.Unlock()
		device, conflicts := registry.find(configuration, identities)
		if device != nil {
			device.attach(ep)
			ep.device = device
			ep.endpoint = device.endpoint
			logger.Info("shares the WireGuard device of endpoint[", device.primary().Tag(), "]")
			return ep, nil
		}
		for _, conflict := range conflicts {
			logger.Warn("endpoint[", conflict, "] holds the same WireGuard key for the same peer with other settings: the peer keeps one session per key, so the two endpoints will take it from each other")
		}
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: options.DialerOptions,
		RemoteIsDomain: common.Any(options.Peers, func(it option.WireGuardPeer) bool {
			return !M.ParseAddr(it.Address).IsValid()
		}),
		// The transport dials a lone peer through the detour by name, so the
		// detour resolves it unless a domain resolver says otherwise, as for any
		// outbound; several peers are resolved here and raced.
		ResolverOnDetour: len(options.Peers) > 1,
	})
	if err != nil {
		return nil, err
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	device := &sharedDevice{registry: registry, configuration: configuration, identities: identities}
	wgEndpoint, err := wireguard.NewEndpoint(wireguard.EndpointOptions{
		Context:         ctx,
		Logger:          logger,
		System:          options.System,
		Handler:         device,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		UDPMapping:      tun.NATMapping(options.UDPMapping),
		UDPFiltering:    tun.NATFiltering(options.UDPFiltering),
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: networkManager.InterfaceFinder(),
		EgressPoolOptions: tun.UDPEgressPoolOptions{
			Logger:           logger,
			InterfaceFinder:  networkManager.InterfaceFinder(),
			InterfaceMonitor: networkManager.InterfaceMonitor(),
			ExcludeInterface: options.Name,
			IsExempt: func() bool {
				return networkManager.AutoRedirectOutputMark() != 0
			},
		},
		Dialer: outboundDialer,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					BindInterface:      interfaceName,
					UDPFragmentDefault: true,
				},
			}))
		},
		Tag:        tag,
		Name:       options.Name,
		MTU:        options.MTU,
		Address:    options.Address,
		PrivateKey: options.PrivateKey,
		ListenPort: options.ListenPort,
		ResolvePeer: func(domain string) ([]netip.Addr, error) {
			return ep.dnsRouter.Lookup(ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
		},
		Peers: common.Map(options.Peers, func(it option.WireGuardPeer) wireguard.PeerOptions {
			return wireguard.PeerOptions{
				Endpoint:                    M.ParseSocksaddrHostPort(it.Address, it.Port),
				PublicKey:                   it.PublicKey,
				PreSharedKey:                it.PreSharedKey,
				AllowedIPs:                  it.AllowedIPs,
				PersistentKeepaliveInterval: it.PersistentKeepaliveInterval,
				Reserved:                    it.Reserved,
			}
		}),
		Workers: options.Workers,
		Amnezia: amnezia,
	})
	if err != nil {
		return nil, err
	}
	device.endpoint = wgEndpoint
	device.attach(ep)
	ep.device = device
	ep.endpoint = wgEndpoint
	if registry != nil {
		registry.devices = append(registry.devices, device)
	}
	return ep, nil
}

func (w *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(func() error {
			return w.device.release(w)
		})
	case adapter.StartStateStart:
		return w.device.start(false)
	case adapter.StartStatePostStart:
		err := w.device.start(true)
		if err != nil {
			return err
		}
		w.started.Store(true)
		scope.Add(func() error {
			w.device.bindAccess.Lock()
			w.started.Store(false)
			w.device.bindAccess.Unlock()
			return nil
		})
	}
	return nil
}

func (w *Endpoint) InterfaceUpdated(ctx context.Context) {
	if !w.started.Load() || w.device.primary() != w {
		return
	}
	go w.updateBind(ctx)
}

func (w *Endpoint) updateBind(ctx context.Context) {
	w.device.bindAccess.Lock()
	defer w.device.bindAccess.Unlock()
	if ctx.Err() != nil || !w.started.Load() {
		return
	}
	err := w.endpoint.BindUpdate()
	if err != nil {
		w.logger.Error(E.Cause(err, "update bind"))
	}
}

func (w *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (w *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return w.endpoint.PortAddresses()
}

func (w *Endpoint) PortMTU() uint32 {
	return w.endpoint.PortMTU()
}

func (w *Endpoint) AttachReturn(returnPath tun.Return) error {
	return w.endpoint.AttachReturn(returnPath)
}

func (w *Endpoint) DetachReturn(returnPath tun.Return) error {
	return w.endpoint.DetachReturn(returnPath)
}

func (w *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr()) {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	return adapter.JudgeFlow(w.router, adapter.InboundContext{Inbound: w.Tag(), InboundType: w.Type()}, network, source, destination, firstPacket)
}

func (w *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(w.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	w.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	w.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (w *Endpoint) WritePackets(packets [][]byte) error {
	if !w.started.Load() {
		return E.New("WireGuard is not ready yet")
	}
	return w.endpoint.WritePackets(packets)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	w.logger.InfoContext(ctx, "inbound packet connection from ", source)
	w.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	w.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if !w.started.Load() {
		return nil, E.New("WireGuard is not ready yet")
	}
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.endpoint, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if !w.started.Load() {
		return nil, netip.Addr{}, E.New("WireGuard is not ready yet")
	}
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, w.endpoint, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(w.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := w.endpoint.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(w.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(w.logger, packetConn), netip.Addr{}, nil
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := w.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (w *Endpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

func (w *Endpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if !w.started.Load() {
		return false
	}
	return w.endpoint.Lookup(address) != nil
}
