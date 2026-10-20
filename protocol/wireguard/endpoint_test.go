package wireguard

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestOneSidedAmneziaOptions(t *testing.T) {
	if oneSidedAmneziaOptions(nil) != nil || amneziaOptions(nil) != nil {
		t.Fatal("expected no Amnezia options")
	}
	oneSided := oneSidedAmneziaOptions(&option.OneSidedAmnezia{JC: 4, I1: "<r 2>", DisableCookies: true})
	if oneSided.JC != 4 || oneSided.I1 != "<r 2>" || !oneSided.DisableCookies {
		t.Fatal("one-sided parameters were not carried")
	}
	if oneSided.S1 != 0 || oneSided.H1 != nil || oneSided.HeaderProtectionKey != "" || oneSided.RandomTrailers {
		t.Fatal("a WireGuard peer must not receive two-sided parameters")
	}
}

func TestAmneziaOptions(t *testing.T) {
	header := option.Range[uint32]{From: 100, To: 200}
	amnezia := amneziaOptions(&option.WireGuardAmnezia{
		OneSidedAmnezia:     option.OneSidedAmnezia{JC: 4, DisableCookies: true},
		S1:                  64,
		H1:                  &header,
		HeaderProtectionKey: "key",
		RandomTrailers:      true,
	})
	if amnezia.JC != 4 || !amnezia.DisableCookies {
		t.Fatal("one-sided parameters were not carried")
	}
	if amnezia.S1 != 64 || amnezia.H1 != &header || amnezia.HeaderProtectionKey != "key" || !amnezia.RandomTrailers {
		t.Fatal("two-sided parameters were not carried")
	}
}
