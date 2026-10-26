package force_close

import (
	"io"
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
	case io.Closer:
		// HTTP/3's transport and XHTTP's over several QUIC connections close their connections themselves
		transport.Close()
		return rawTransport
	default:
		panic(E.New("unknown transport type: ", reflect.TypeOf(transport)))
	}
}

type efaceWords struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}
