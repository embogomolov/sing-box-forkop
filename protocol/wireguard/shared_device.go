package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// A WireGuard server keeps one session per client key, so two devices holding one key take it from
// each other. Endpoints of a box that differ only in their tag therefore share one device, each
// keeping its own tag, type and place in groups.
type sharedDevice struct {
	registry      *deviceRegistry
	configuration string
	identities    []string
	endpoint      *wireguard.Endpoint
	bindAccess    sync.Mutex
	startAccess   sync.Mutex
	started       [2]bool
	startErr      [2]error
	access        sync.Mutex
	members       []*Endpoint
	closing       bool
}

type deviceRegistry struct {
	access  sync.Mutex
	devices []*sharedDevice
}

type deviceConfiguration struct {
	Type    string                        `json:"type"`
	Options option.WireGuardCommonOptions `json:"options"`
	Amnezia *wireguard.AmneziaOptions     `json:"amnezia,omitempty"`
}

var registryAccess sync.Mutex

func deviceRegistryFromContext(ctx context.Context) *deviceRegistry {
	if service.RegistryFromContext(ctx) == nil {
		return nil
	}
	registryAccess.Lock()
	defer registryAccess.Unlock()
	registry := service.PtrFromContext[deviceRegistry](ctx)
	if registry == nil {
		registry = new(deviceRegistry)
		service.MustRegisterPtr(ctx, registry)
	}
	return registry
}

func sharedDeviceKey(endpointType string, options option.WireGuardCommonOptions, amnezia *wireguard.AmneziaOptions) (string, []string, error) {
	content, err := json.Marshal(deviceConfiguration{Type: endpointType, Options: options, Amnezia: amnezia})
	if err != nil {
		return "", nil, err
	}
	identities := make([]string, 0, len(options.Peers))
	for _, peer := range options.Peers {
		identities = append(identities, options.PrivateKey+"/"+peer.PublicKey)
	}
	return string(content), identities, nil
}

// find returns the running device with this configuration and the tags of the
// devices that hold one of its keys with other settings. The caller holds access.
func (r *deviceRegistry) find(configuration string, identities []string) (*sharedDevice, []string) {
	var conflicts []string
	for _, device := range r.devices {
		if device.configuration == configuration {
			if device.attachable() {
				return device, nil
			}
			continue
		}
		if slices.ContainsFunc(identities, func(identity string) bool {
			return slices.Contains(device.identities, identity)
		}) {
			conflicts = append(conflicts, device.tags()...)
		}
	}
	return nil, conflicts
}

func (r *deviceRegistry) remove(device *sharedDevice) {
	r.access.Lock()
	defer r.access.Unlock()
	r.devices = slices.DeleteFunc(r.devices, func(it *sharedDevice) bool {
		return it == device
	})
}

func (d *sharedDevice) attachable() bool {
	d.access.Lock()
	defer d.access.Unlock()
	return !d.closing
}

func (d *sharedDevice) attach(member *Endpoint) {
	d.access.Lock()
	defer d.access.Unlock()
	d.members = append(d.members, member)
}

func (d *sharedDevice) tags() []string {
	d.access.Lock()
	defer d.access.Unlock()
	tags := make([]string, 0, len(d.members))
	for _, member := range d.members {
		tags = append(tags, member.Tag())
	}
	return tags
}

func (d *sharedDevice) primary() *Endpoint {
	d.access.Lock()
	defer d.access.Unlock()
	if len(d.members) == 0 {
		return nil
	}
	return d.members[0]
}

// start runs each start phase of the device once, for whichever member reaches
// it first, and hands every later member the same result.
func (d *sharedDevice) start(postStart bool) error {
	d.startAccess.Lock()
	defer d.startAccess.Unlock()
	phase := 0
	if postStart {
		phase = 1
	}
	if !d.started[phase] {
		d.started[phase] = true
		d.startErr[phase] = d.endpoint.Start(postStart)
	}
	return d.startErr[phase]
}

// release closes the device with the last member that leaves it.
func (d *sharedDevice) release(member *Endpoint) error {
	d.access.Lock()
	d.members = slices.DeleteFunc(d.members, func(it *Endpoint) bool {
		return it == member
	})
	last := len(d.members) == 0
	if last {
		d.closing = true
	}
	d.access.Unlock()
	if !last {
		return nil
	}
	if d.registry != nil {
		d.registry.remove(d)
	}
	d.bindAccess.Lock()
	defer d.bindAccess.Unlock()
	return d.endpoint.Close()
}

func (d *sharedDevice) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	member := d.primary()
	if member == nil {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	return member.JudgeFlow(network, source, destination, firstPacket)
}

func (d *sharedDevice) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	member := d.primary()
	if member == nil {
		return
	}
	member.NewDNSPacket(payload, source, destination, writer)
}

func (d *sharedDevice) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	member := d.primary()
	if member == nil {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrClosed)
		return
	}
	member.NewConnectionEx(ctx, conn, source, destination, onClose)
}

func (d *sharedDevice) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	member := d.primary()
	if member == nil {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrClosed)
		return
	}
	member.NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}

var _ tun.Handler = (*sharedDevice)(nil)
