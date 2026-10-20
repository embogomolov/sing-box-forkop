//go:build with_ssh

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/ssh"
)

func registerSSHOutbound(registry *outbound.Registry) {
	ssh.RegisterOutbound(registry)
}
