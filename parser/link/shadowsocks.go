package link

import (
	"net/url"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseShadowsocksLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing user info")
	}
	var options option.ShadowsocksOutboundOptions
	options.ServerOptions.Server = linkURL.Hostname()
	options.ServerOptions.ServerPort = common.StringToType[uint16](linkURL.Port())
	password, _ := linkURL.User.Password()
	if password == "" {
		return option.Outbound{}, E.New("bad user info")
	}
	options.Method = linkURL.User.Username()
	options.Password = password
	plugin := linkURL.Query().Get("plugin")
	options.Plugin = shadowsocksPluginName(plugin)
	options.PluginOptions = shadowsocksPluginOptions(plugin)

	outbound := option.Outbound{
		Type: C.TypeShadowsocks,
		Tag:  linkURL.Fragment,
	}
	outbound.Options = &options
	return outbound, nil
}
