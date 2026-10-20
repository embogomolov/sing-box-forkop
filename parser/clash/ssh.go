package clash

import (
	"strings"

	"github.com/sagernet/sing-box/option"
)

type SSHOption struct {
	DialerOptions        `yaml:",inline"`
	ServerOptions        `yaml:",inline"`
	UserName             string   `yaml:"username"`
	Password             string   `yaml:"password,omitempty"`
	PrivateKey           string   `yaml:"private-key,omitempty"`
	PrivateKeyPassphrase string   `yaml:"private-key-passphrase,omitempty"`
	HostKey              []string `yaml:"host-key,omitempty"`
	HostKeyAlgorithms    []string `yaml:"host-key-algorithms,omitempty"`
}

func (s *SSHOption) Build() any {
	options := &option.SSHOutboundOptions{
		DialerOptions:        s.DialerOptions.Build(),
		ServerOptions:        s.ServerOptions.Build(),
		User:                 s.UserName,
		Password:             s.Password,
		PrivateKeyPassphrase: s.PrivateKeyPassphrase,
		HostKey:              s.HostKey,
		HostKeyAlgorithms:    s.HostKeyAlgorithms,
	}
	if strings.Contains(s.PrivateKey, "PRIVATE KEY") {
		options.PrivateKey = trimStringArray(strings.Split(s.PrivateKey, "\n"))
	} else {
		options.PrivateKeyPath = s.PrivateKey
	}
	return options
}
