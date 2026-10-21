//go:build with_gvisor

package tailscale

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/health/healthmsg"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
)

var _ adapter.TailscaleStatusReporter = (*Endpoint)(nil)

func (t *Endpoint) TailscaleStatus() adapter.TailscaleStatus {
	result := adapter.TailscaleStatus{
		Tag:                t.Tag(),
		State:              ipn.Starting.String(),
		AdvertisesExitNode: t.advertiseExitNode,
		Addresses:          []string{},
		Routes:             []adapter.TailscaleRouteStatus{},
		Health:             []string{},
		Peers:              []adapter.TailscalePeerStatus{},
	}
	if !t.started.Load() {
		return result
	}
	status := t.server.ExportLocalBackend().Status()
	result.State = status.BackendState
	result.AuthURL = status.AuthURL
	if status.CurrentTailnet != nil {
		result.Tailnet = status.CurrentTailnet.Name
	}
	for _, message := range status.Health {
		// accept_routes is an option of its own; the warning names the CLI flag instead.
		if message != healthmsg.WarnAcceptRoutesOff {
			result.Health = append(result.Health, message)
		}
	}
	var approved []netip.Prefix
	if self := status.Self; self != nil {
		result.Connected = self.Online
		result.Name = machineName(self)
		result.DNSName = strings.TrimSuffix(self.DNSName, ".")
		for _, address := range self.TailscaleIPs {
			result.Addresses = append(result.Addresses, address.String())
		}
		if self.KeyExpiry != nil {
			result.KeyExpiry = self.KeyExpiry.Unix()
		}
		result.ExitNodeApproved = self.ExitNodeOption
		if self.AllowedIPs != nil {
			approved = self.AllowedIPs.AsSlice()
		}
	}
	for _, prefix := range t.advertiseRoutes {
		result.Routes = append(result.Routes, adapter.TailscaleRouteStatus{
			Prefix:   prefix.String(),
			Approved: slices.Contains(approved, prefix),
		})
	}
	for _, peerKey := range status.Peers() {
		peer := status.Peer[peerKey]
		peerStatus := adapter.TailscalePeerStatus{
			Name:           machineName(peer),
			DNSName:        strings.TrimSuffix(peer.DNSName, "."),
			Addresses:      make([]string, 0, len(peer.TailscaleIPs)),
			Online:         peer.Online,
			ExitNodeOption: peer.ExitNodeOption,
		}
		if profile, loaded := status.User[peer.UserID]; loaded {
			peerStatus.User = profile.LoginName
		}
		for _, address := range peer.TailscaleIPs {
			peerStatus.Addresses = append(peerStatus.Addresses, address.String())
		}
		if !peer.Online && !peer.LastSeen.IsZero() {
			peerStatus.LastSeen = peer.LastSeen.Unix()
		}
		result.Peers = append(result.Peers, peerStatus)
	}
	slices.SortStableFunc(result.Peers, func(a, b adapter.TailscalePeerStatus) int {
		if a.Online != b.Online {
			if a.Online {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

// machineName is the name the admin console shows and an exit node is chosen by: the first
// label of the MagicDNS name, or the host name without MagicDNS.
func machineName(peer *ipnstate.PeerStatus) string {
	if label, _, _ := strings.Cut(peer.DNSName, "."); label != "" {
		return label
	}
	return peer.HostName
}
