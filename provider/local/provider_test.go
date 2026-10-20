package provider_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestCoreStartsWhenALocalProviderHasNoUsableOutbounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.json")
	subscription := `{"outbounds": [{"type": "shadowsocks", "tag": "broken", "server": "198.51.100.1", "server_port": 443, "method": "no-such-method", "password": "secret"}]}`
	if err := os.WriteFile(path, []byte(subscription), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"providers": [{"type": "local", "tag": "subscription", "path": `+strconv.Quote(path)+`}],
		"outbounds": [
			{"type": "selector", "tag": "proxy", "providers": ["subscription"]},
			{"type": "direct", "tag": "direct"}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
}
