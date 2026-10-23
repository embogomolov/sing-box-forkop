package adapter

// TailscaleStatusReporter is a Tailscale endpoint that reports its state through the Clash API.
type TailscaleStatusReporter interface {
	Endpoint
	TailscaleStatus() TailscaleStatus
}

// TailscaleStatus is one Tailscale endpoint as the Clash API reports it.
type TailscaleStatus struct {
	Tag   string `json:"tag"`
	State string `json:"state"`
	// AuthURL is where the device is signed in while State is NeedsLogin.
	AuthURL string `json:"authURL,omitempty"`
	// Connected reports a live session with the coordination server.
	Connected bool     `json:"connected"`
	Name      string   `json:"name,omitempty"`
	DNSName   string   `json:"dnsName,omitempty"`
	Tailnet   string   `json:"tailnet,omitempty"`
	Addresses []string `json:"addresses"`
	// KeyExpiry is when the node key expires, in Unix seconds; zero when it never does.
	KeyExpiry int64 `json:"keyExpiry,omitempty"`
	// ExitNode is the exit node the endpoint is set to use, a name or an address as its options give it.
	ExitNode           string                 `json:"exitNode,omitempty"`
	AdvertisesExitNode bool                   `json:"advertisesExitNode"`
	ExitNodeApproved   bool                   `json:"exitNodeApproved"`
	Routes             []TailscaleRouteStatus `json:"routes"`
	Health             []string               `json:"health"`
	Peers              []TailscalePeerStatus  `json:"peers"`
}

// TailscaleRouteStatus is a subnet the endpoint advertises and whether the tailnet approved it.
type TailscaleRouteStatus struct {
	Prefix   string `json:"prefix"`
	Approved bool   `json:"approved"`
}

// TailscalePeerStatus is another device of the tailnet as the endpoint sees it.
type TailscalePeerStatus struct {
	Name      string   `json:"name"`
	DNSName   string   `json:"dnsName,omitempty"`
	Addresses []string `json:"addresses"`
	// Subnets are the routes the tailnet reaches through this device, exit routes aside.
	Subnets []string `json:"subnets,omitempty"`
	Online  bool     `json:"online"`
	// LastSeen is in Unix seconds; zero for a peer online now or never seen.
	LastSeen       int64 `json:"lastSeen,omitempty"`
	ExitNodeOption bool  `json:"exitNodeOption"`
	// ExitNode reports the device the endpoint sends internet traffic through.
	ExitNode bool `json:"exitNode"`
}
