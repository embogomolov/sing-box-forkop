package force_close

import (
	"net/http"
	"reflect"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

func ResetTransport(rawTransport http.RoundTripper) http.RoundTripper {
	switch transport := rawTransport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
		return transport.Clone()
	case *http2.Transport:
		CloseHTTP2Connections(transport)
		return transport
	default:
		if reset, ok := resetHTTP3Transport(rawTransport); ok {
			return reset
		}
		panic(E.New("unknown transport type: ", reflect.TypeOf(transport)))
	}
}

type efaceWords struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}
