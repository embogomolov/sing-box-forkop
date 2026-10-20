package warp

import "github.com/sagernet/sing-box/common/cloudflare"

type Config struct {
	PrivateKey string `json:"private_key"`
	Interface  struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []cloudflare.Peer
}
