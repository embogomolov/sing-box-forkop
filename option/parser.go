package option

type ParserOutboundOptions struct {
	DialerOptions
	Link string `json:"link"`
}
