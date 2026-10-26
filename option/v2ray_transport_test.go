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

// What can only fail every dial is refused when the configuration is read: a method that is no HTTP token,
// a download leg without its server or port.
func TestXHTTPRefusesWhatFailsEveryDial(t *testing.T) {
	for _, test := range []struct{ content, message string }{
		{`{"type":"xhttp","mode":"packet-up","uplink_http_method":"PO ST"}`, "uplink_http_method"},
		{`{"type":"xhttp","mode":"packet-up","download":{"server":"down.example","server_port":443,"uplink_http_method":"P\"UT"}}`, "uplink_http_method"},
		{`{"type":"xhttp","download":{"server_port":443}}`, "download: missing server"},
		{`{"type":"xhttp","download":{"server":"down.example"}}`, "download: missing server_port"},
	} {
		var transport V2RayTransportOptions
		require.ErrorContains(t, json.UnmarshalContext(context.Background(), []byte(test.content), &transport), test.message, test.content)
	}
	var transport V2RayTransportOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"type":"xhttp","mode":"packet-up","uplink_http_method":"put"}`), &transport))
	require.Equal(t, "PUT", transport.XHTTPOptions.UplinkHTTPMethod)
}
