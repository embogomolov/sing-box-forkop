package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// An XHTTP leg that names no padding range gets Xray's, 100 to 1000 bytes, which an Xray server checks the
// requests against; a range with a bound of zero or less is refused, as Xray refuses it.
func TestXHTTPPaddingDefaultsAsXray(t *testing.T) {
	download := func(padding string) string {
		return `"download":{"server":"down.example","server_port":443` + padding + `}`
	}
	for _, padding := range []string{``, `,"x_padding_bytes":0`} {
		var transport V2RayTransportOptions
		content := `{"type":"xhttp","path":"/x"` + padding + `,` + download(padding) + `}`
		require.NoError(t, json.UnmarshalContext(context.Background(), []byte(content), &transport), content)
		require.Equal(t, Range[int]{From: 100, To: 1000}, transport.XHTTPOptions.XPaddingBytes, content)
		require.Equal(t, Range[int]{From: 100, To: 1000}, transport.XHTTPOptions.Download.XPaddingBytes, content)
	}
	for _, padding := range []string{`"0-100"`, `-1`} {
		for _, content := range []string{
			`{"type":"xhttp","x_padding_bytes":` + padding + `}`,
			`{"type":"xhttp","x_padding_bytes":"100-200",` + download(`,"x_padding_bytes":`+padding) + `}`,
		} {
			var transport V2RayTransportOptions
			err := json.UnmarshalContext(context.Background(), []byte(content), &transport)
			require.ErrorContains(t, err, "x_padding_bytes cannot be disabled", content)
		}
	}
}
