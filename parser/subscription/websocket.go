package subscription

import (
	"net/url"
	"strconv"
)

// SplitWebsocketEarlyData takes the "ed" early data length out of a WebSocket path. Xray, Clash and
// their links strip it before the request and send early data in Sec-WebSocket-Protocol; left in
// the path, it asks the server for a resource it does not serve.
func SplitWebsocketEarlyData(path string) (string, uint32) {
	parsed, err := url.Parse(path)
	if err != nil {
		return path, 0
	}
	query := parsed.Query()
	value := query.Get("ed")
	if value == "" {
		return path, 0
	}
	length, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return path, 0
	}
	query.Del("ed")
	parsed.RawQuery = query.Encode()
	return parsed.String(), uint32(length)
}
