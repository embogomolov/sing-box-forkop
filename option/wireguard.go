package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardCommonOptions struct {
	System       bool                             `json:"system,omitempty"`
	Name         string                           `json:"name,omitempty"`
	MTU          uint32                           `json:"mtu,omitempty"`
	Address      badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey   string                           `json:"private_key"`
	ListenPort   uint16                           `json:"listen_port,omitempty"`
	Peers        []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout   badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping   UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax    uint32                           `json:"udp_nat_max,omitempty"`
	Workers      int                              `json:"workers,omitempty"`
	DialerOptions
}

// A WireGuard peer may be any implementation, so this endpoint takes only the obfuscation one side
// adds alone: junk and signature packets any peer drops, content padding trimmed with the
// plaintext, and local timings. Parameters both ends must agree on belong to amneziawg.
type WireGuardEndpointOptions struct {
	WireGuardCommonOptions
	Amnezia *OneSidedAmnezia `json:"amnezia,omitempty"`
}

// The whole AmneziaWG parameter set, including what must match the other end exactly.
type AmneziaWGEndpointOptions struct {
	WireGuardCommonOptions
	Amnezia *WireGuardAmnezia `json:"amnezia,omitempty"`
}

// OneSidedAmnezia carries the AmneziaWG parameters that need no agreement from
// the peer. It is shared by the WireGuard and WARP endpoints, whose peers are a
// plain WireGuard implementation and Cloudflare respectively.
type OneSidedAmnezia struct {
	JC                     int            `json:"jc,omitempty"`
	JMin                   int            `json:"jmin,omitempty"`
	JMax                   int            `json:"jmax,omitempty"`
	I1                     string         `json:"i1,omitempty"`
	I2                     string         `json:"i2,omitempty"`
	I3                     string         `json:"i3,omitempty"`
	I4                     string         `json:"i4,omitempty"`
	I5                     string         `json:"i5,omitempty"`
	ContentPaddingAddition *Range[uint32] `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         *Range[uint32] `json:"rekey_after_time,omitempty"`
	RekeyTimeout           *Range[uint32] `json:"rekey_timeout,omitempty"`
	RejectAfterTime        *Range[uint32] `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       *Range[uint32] `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   *Range[uint32] `json:"max_handshake_attempts,omitempty"`
	DisableCookies         bool           `json:"disable_cookies,omitempty"`
}

type WireGuardPeer struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval *Range[uint32]                   `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []uint8                          `json:"reserved,omitempty"`
}

// The parameters that describe the wire itself: magic headers, their pseudorandom prefix and the
// header protection key. A peer without the same values cannot recognize a packet.
type WireGuardAmnezia struct {
	OneSidedAmnezia
	S1                  int            `json:"s1,omitempty"`
	S2                  int            `json:"s2,omitempty"`
	S3                  int            `json:"s3,omitempty"`
	S4                  int            `json:"s4,omitempty"`
	H1                  *Range[uint32] `json:"h1,omitempty"`
	H2                  *Range[uint32] `json:"h2,omitempty"`
	H3                  *Range[uint32] `json:"h3,omitempty"`
	H4                  *Range[uint32] `json:"h4,omitempty"`
	HeaderProtectionKey string         `json:"header_protection_key,omitempty"`
	RandomTrailers      bool           `json:"random_trailers,omitempty"`
}
