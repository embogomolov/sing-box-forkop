package option

import "github.com/sagernet/sing/common/json/badoption"

type WARPEndpointOptions struct {
	System                      bool               `json:"system,omitempty"`
	Name                        string             `json:"name,omitempty"`
	ListenPort                  uint16             `json:"listen_port,omitempty"`
	UDPTimeout                  badoption.Duration `json:"udp_timeout,omitempty"`
	PersistentKeepaliveInterval *Range[uint32]     `json:"persistent_keepalive_interval,omitempty"`
	Workers                     int                `json:"workers,omitempty"`
	Amnezia                     *OneSidedAmnezia   `json:"amnezia,omitempty"`
	Profile                     CloudflareProfile  `json:"profile,omitempty"`
	Address                     string             `json:"address,omitempty"`
	Port                        uint16             `json:"port,omitempty"`
	DialerOptions
}
