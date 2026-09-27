package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestInitializeErrorNamesTheFailingElement(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "shadowsocks", "tag": "Proxy/node", "server": "127.0.0.1", "server_port": 443, "method": "no-such-cipher", "password": "x"}
		]
	}`))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.ErrorContains(t, err, "initialize outbound[1] shadowsocks[Proxy/node]: ")
}
