//go:build !with_mieru

package link

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseMieruLink(link string) (option.Outbound, error) {
	return option.Outbound{}, E.New("mieru is not included in this build, rebuild with -tags with_mieru")
}
