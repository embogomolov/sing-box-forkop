package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/congestion"
	sbdialer "github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/common/xray/pipe"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
)

var _ adapter.V2RayMultiplexClientTransport = (*Client)(nil)

// headerUploadSize is a post of upload data carried in headers or cookies when the node sets no size:
// Xray's megabyte is far over the 8 KiB of headers a server takes, 4 KiB fits beside the padding.
const headerUploadSize = 4096

type Client struct {
	ctx             context.Context
	options         *option.V2RayXHTTPOptions
	mode            string
	baseRequestURL  url.URL
	baseRequestURL2 url.URL
	getHTTPClient   func() (DialerClient, *XmuxClient)
	getHTTPClient2  func() (DialerClient, *XmuxClient)
	xmuxManager     *XmuxManager
	xmuxManager2    *XmuxManager
	multiplex       bool
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if tlsConfig != nil && len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{"h2"})
	}
	if err := checkHTTP3(tlsConfig); err != nil {
		return nil, err
	}
	if _, err := congestion.NewCongestionControl(options.CongestionController, options.CWND, nil); err != nil {
		return nil, err
	}
	if options.Download != nil {
		if _, err := congestion.NewCongestionControl(options.Download.CongestionController, options.Download.CWND, nil); err != nil {
			return nil, err
		}
	}
	dest := serverAddr
	baseRequestURL, err := getBaseRequestURL(&options.V2RayXHTTPBaseOptions, dest, tlsConfig)
	if err != nil {
		return nil, err
	}
	var xmuxOptions option.V2RayXHTTPXmuxOptions
	if options.Xmux != nil {
		xmuxOptions = *options.Xmux
	}
	xmuxManager := NewXmuxManager(xmuxOptions, func() XmuxConn {
		return createHTTPClient(ctx, dest, dialer, &options.V2RayXHTTPBaseOptions, tlsConfig)
	})
	getHTTPClient := func() (DialerClient, *XmuxClient) {
		xmuxClient := xmuxManager.GetXmuxClient(ctx)
		return xmuxClient.XmuxConn.(DialerClient), xmuxClient
	}
	baseRequestURL2 := baseRequestURL
	getHTTPClient2 := getHTTPClient
	var xmuxManager2 *XmuxManager
	multiplex := decideHTTPVersion(tlsConfig) != "1.1"
	if options.Download != nil {
		options2 := options.Download
		dialer2 := dialer
		if options2.Detour != "" {
			var ok bool
			dialer2, ok = service.FromContext[adapter.OutboundManager](ctx).Outbound(options2.Detour)
			if !ok {
				return nil, E.New("outbound detour not found: ", options2.Detour)
			}
		} else if M.IsDomainName(options2.Server) && !serverAddr.IsFqdn() {
			// the dialer of an outbound whose server is an address resolves no names
			dialer2 = sbdialer.NewResolveDialer(ctx, dialer, false, "", adapter.DNSQueryOptions{}, 0)
		}
		dest2 := options2.ServerOptions.Build()
		var tlsConfig2 tls.Config
		if options2.TLS != nil {
			tlsConfig2, err = tls.NewClient(ctx, log.StdLogger(), options2.Server, common.PtrValueOrDefault(options2.TLS))
			if err != nil {
				return nil, err
			}
		}
		if tlsConfig2 != nil && len(tlsConfig2.NextProtos()) == 0 {
			tlsConfig2.SetNextProtos([]string{"h2"})
		}
		if err = checkHTTP3(tlsConfig2); err != nil {
			return nil, E.Cause(err, "download")
		}
		multiplex = multiplex && decideHTTPVersion(tlsConfig2) != "1.1"
		baseRequestURL2, err = getBaseRequestURL(&options2.V2RayXHTTPBaseOptions, dest2, tlsConfig2)
		if err != nil {
			return nil, err
		}
		var xmuxOptions2 option.V2RayXHTTPXmuxOptions
		if options2.Xmux != nil {
			xmuxOptions2 = *options2.Xmux
		}
		xmuxManager2 = NewXmuxManager(xmuxOptions2, func() XmuxConn {
			return createHTTPClient(ctx, dest2, dialer2, &options2.V2RayXHTTPBaseOptions, tlsConfig2)
		})
		getHTTPClient2 = func() (DialerClient, *XmuxClient) {
			xmuxClient2 := xmuxManager2.GetXmuxClient(ctx)
			return xmuxClient2.XmuxConn.(DialerClient), xmuxClient2
		}
	}
	return &Client{
		ctx:             ctx,
		options:         &options,
		mode:            resolveMode(options.Mode, tlsConfig, options.Download != nil),
		getHTTPClient:   getHTTPClient,
		getHTTPClient2:  getHTTPClient2,
		baseRequestURL:  baseRequestURL,
		baseRequestURL2: baseRequestURL2,
		xmuxManager:     xmuxManager,
		xmuxManager2:    xmuxManager2,
		multiplex:       multiplex,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	options := c.options
	mode := c.mode
	sessionId := ""
	if mode != "stream-one" {
		sessionId = GenerateSessionID(&c.options.V2RayXHTTPBaseOptions)
	}
	requestURL := c.baseRequestURL
	requestURL2 := c.baseRequestURL2
	httpClient, xmuxClient := c.getHTTPClient()
	httpClient2, xmuxClient2 := c.getHTTPClient2()
	if xmuxClient != nil {
		xmuxClient.AddOpenUsage(1)
	}
	if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
		xmuxClient2.AddOpenUsage(1)
	}
	var closed atomic.Int32
	reader, writer := io.Pipe()
	conn := splitConn{
		writer: writer,
		onClose: func() {
			if closed.Add(1) > 1 {
				return
			}
			if xmuxClient != nil {
				xmuxClient.AddOpenUsage(-1)
			}
			if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
				xmuxClient2.AddOpenUsage(-1)
			}
		},
	}
	var err error
	if mode == "stream-one" {
		requestURL.Path = options.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, false)
		if err != nil { // browser dialer only
			return nil, err
		}
		return &conn, nil
	} else { // stream-down
		if xmuxClient2 != nil {
			xmuxClient2.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(ctx, requestURL2.String(), sessionId, nil, false)
		if err != nil { // browser dialer only
			return nil, err
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, true)
		if err != nil { // browser dialer only
			return nil, err
		}
		return &conn, nil
	}
	scMaxEachPostBytes := options.GetNormalizedScMaxEachPostBytes()
	if (options.ScMaxEachPostBytes == nil || options.ScMaxEachPostBytes.To == 0) &&
		(options.UplinkDataPlacement == option.PlacementHeader || options.UplinkDataPlacement == option.PlacementCookie) {
		scMaxEachPostBytes = option.Range[int]{From: headerUploadSize, To: headerUploadSize}
	}
	scMinPostsIntervalMs := options.GetNormalizedScMinPostsIntervalMs()
	maxUploadSize := int32(scMaxEachPostBytes.Rand())
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	// uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(max(0, maxUploadSize-buf.Size)))
	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}
	go func() {
		var seq int64
		var lastWrite time.Time
		dynamicHTTPClient := httpClient
		dynamicXmuxClient := xmuxClient
		for {
			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			remainder, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			doSplit := atomic.Bool{}
			for doSplit.Store(true); doSplit.Load(); {
				var chunk buf.MultiBuffer
				remainder, chunk = buf.SplitSize(remainder, maxUploadSize)
				if chunk.IsEmpty() {
					break
				}
				wroteRequest := done.New()
				ctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
					WroteRequest: func(httptrace.WroteRequestInfo) {
						wroteRequest.Close()
					},
				})
				seqStr := strconv.FormatInt(seq, 10)
				seq += 1
				if scMinPostsIntervalMs.From > 0 {
					time.Sleep(time.Duration(scMinPostsIntervalMs.Rand())*time.Millisecond - time.Since(lastWrite))
				}
				lastWrite = time.Now()
				if dynamicXmuxClient != nil && (dynamicXmuxClient.LeftRequests.Add(-1) <= 0 ||
					(dynamicXmuxClient.UnreusableAt != time.Time{} && lastWrite.After(dynamicXmuxClient.UnreusableAt))) {
					dynamicHTTPClient, dynamicXmuxClient = c.getHTTPClient()
				}
				go func(hClient DialerClient) {
					err := hClient.PostPacket(
						ctx,
						requestURL.String(),
						sessionId,
						seqStr,
						chunk,
					)
					wroteRequest.Close()
					if err != nil {
						uploadPipeReader.Interrupt()
						doSplit.Store(false)
					}
				}(dynamicHTTPClient)
				if _, ok := dynamicHTTPClient.(*DefaultDialerClient); ok {
					<-wroteRequest.Wait()
				}
			}
		}
	}()
	return &conn, nil
}

// MultiplexEnabled reports pooled HTTP/2 and HTTP/3 connections; over HTTP/1.1 a download opens its own.
func (c *Client) MultiplexEnabled() bool {
	return c.multiplex
}

func (c *Client) Close() error {
	c.xmuxManager.Close()
	if c.xmuxManager2 != nil {
		c.xmuxManager2.Close()
	}
	return nil
}

// resolveMode picks the mode auto stands for as Xray's dialer does: stream-one over REALITY, which no CDN
// can stand in front of, stream-up there with a download leg, and packet-up otherwise.
func resolveMode(mode string, tlsConfig tls.Config, download bool) string {
	if mode != "" && mode != "auto" {
		return mode
	}
	if !isReality(tlsConfig) {
		return "packet-up"
	}
	if download {
		return "stream-up"
	}
	return "stream-one"
}

func isReality(tlsConfig tls.Config) bool {
	switch config := tlsConfig.(type) {
	case *tls.RealityClientConfig:
		return true
	case *tls.KTLSClientConfig:
		return isReality(config.Config)
	default:
		return false
	}
}

// checkHTTP3 refuses a leg over HTTP/3 the build or its TLS cannot carry: QUIC takes no uTLS fingerprint.
func checkHTTP3(tlsConfig tls.Config) error {
	if decideHTTPVersion(tlsConfig) != "3" {
		return nil
	}
	if !C.WithQUIC {
		return C.ErrQUICNotIncluded
	}
	if _, err := tlsConfig.STDConfig(); err != nil {
		return E.Cause(err, "XHTTP over HTTP/3")
	}
	return nil
}

func decideHTTPVersion(tlsConfig tls.Config) string {
	if tlsConfig == nil {
		return "1.1"
	}
	return HTTPVersion(isReality(tlsConfig), tlsConfig.NextProtos())
}

// HTTPVersion is the HTTP version Xray's XHTTP client speaks over TLS, the rule its server listens by:
// HTTP/2 over REALITY, and otherwise HTTP/1.1 or HTTP/3 only for an ALPN of http/1.1 or h3 alone.
func HTTPVersion(reality bool, alpn []string) string {
	if reality || len(alpn) != 1 {
		return "2"
	}
	switch alpn[0] {
	case "http/1.1":
		return "1.1"
	case "h3":
		return "3"
	default:
		return "2"
	}
}

func getBaseRequestURL(options *option.V2RayXHTTPBaseOptions, dest M.Socksaddr, tlsConfig tls.Config) (url.URL, error) {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = options.Host
	if requestURL.Host == "" {
		host := dest
		if tlsConfig != nil && tlsConfig.ServerName() != "" {
			host = M.ParseSocksaddrHostPort(tlsConfig.ServerName(), 0)
		}
		if host.IsIPv6() {
			requestURL.Host = "[" + host.AddrString() + "]"
		} else {
			requestURL.Host = host.AddrString()
		}
	}
	requestURL.Path = options.Path
	if err := sHTTP.URLSetPath(&requestURL, options.Path); err != nil {
		return requestURL, E.New(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	requestURL.Path = options.GetNormalizedPath()
	requestURL.RawQuery = options.GetNormalizedQuery()
	return requestURL, nil
}

func createHTTPClient(ctx context.Context, dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config) DialerClient {
	httpVersion := decideHTTPVersion(tlsConfig)
	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := dialer.DialContext(ctxInner, "tcp", dest)
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil && httpVersion != "3" {
			return tls.ClientHandshake(ctxInner, conn, tlsConfig)
		}
		return conn, nil
	}
	var keepAlivePeriod time.Duration
	if options.Xmux != nil {
		keepAlivePeriod = time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second
	}
	var transport http.RoundTripper
	switch httpVersion {
	case "3":
		transport = newHTTP3Transport(ctx, dest, dialer, options, tlsConfig, keepAlivePeriod)
	case "2":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				conn, err := dialContext(adapter.ContextForMultiplexSession(ctxInner))
				if err != nil {
					return nil, err
				}
				return &frameSizeCapConn{Conn: conn}, nil
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	default:
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}
	client := &DefaultDialerClient{
		options: options,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}
	return client
}
