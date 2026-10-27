//go:build with_quic

package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/net"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// laneRequests is how many requests at a time one QUIC connection is given. A server allows a connection so
// many open streams, 100 by quic-go's default that Xray's server keeps, and quic-go's client then waits for
// a free one where HTTP/2's opens another connection: a node's sessions past about 300 hung on its three
// connections. The margin is for streams the server has not counted closed yet.
const laneRequests = 90

// laneIdleTimeout closes a QUIC connection opened past the first once it has had no request for this long.
const laneIdleTimeout = 30 * time.Second

func newHTTP3Transport(ctx context.Context, dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config, keepAlivePeriod time.Duration) http.RoundTripper {
	if keepAlivePeriod == 0 {
		keepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}
	if keepAlivePeriod < 0 {
		keepAlivePeriod = 0
	}
	congestionControlFactory, _ := congestion.NewCongestionControl(options.CongestionController, options.CWND, ntp.TimeFuncFromContext(ctx))
	quicConfig := &quic.Config{
		MaxIdleTimeout: net.ConnIdleTimeout,
		// these two are defaults of quic-go/http3. the default of quic-go (no
		// http3) is different, so it is hardcoded here for clarity.
		// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
		MaxIncomingStreams: -1,
		KeepAlivePeriod:    keepAlivePeriod,
		// the QUIC handshake of Xray-core's client looks like Chrome's
		ChromeParrot: chromeParrot(tlsConfig),
	}
	return &http3Lanes{newTransport: func(track func(*quic.Conn) bool) *http3.Transport {
		return &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				// the requests that come while the connection is dialed wait for it too: the one that began
				// the dial must not take it down when it is given up
				ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), C.TCPTimeout)
				defer cancel()
				ctx = adapter.ContextForMultiplexSession(ctx)
				udpConn, dErr := dialer.DialContext(ctx, N.NetworkUDP, dest)
				if dErr != nil {
					return nil, dErr
				}
				conn, dErr := qtls.DialEarly(ctx, udpConn, tlsConfig, cfg)
				if dErr != nil {
					_ = udpConn.Close()
					return nil, dErr
				}
				// quic-go does not own the socket: when the connection ends it only stops reading it
				context.AfterFunc(conn.Context(), func() {
					udpConn.Close()
				})
				if congestionControlFactory != nil {
					conn.SetCongestionControl(congestionControlFactory(conn))
				}
				if !track(conn) {
					conn.CloseWithError(0, "")
					return nil, http3.ErrTransportClosed
				}
				return conn, nil
			},
		}
	}}
}

// http3Lanes carries requests over QUIC connections (lanes), one more whenever every lane is full.
type http3Lanes struct {
	newTransport func(track func(*quic.Conn) bool) *http3.Transport

	access sync.Mutex
	lanes  []*http3Lane
	closed bool
}

type http3Lane struct {
	transport *http3.Transport
	// the QUIC connections the lane dialed: quic-go's client forgets one whose request failed without
	// closing it, and the keep-alive then holds it open for good
	conns map[*quic.Conn]struct{}
	// requests on their way, and the timer that closes the lane when there are none
	requests int
	idle     *time.Timer
	// all of them under the lock of the lanes
	closed bool
}

func (l *http3Lanes) RoundTrip(request *http.Request) (*http.Response, error) {
	lane, err := l.acquire()
	if err != nil {
		if request.Body != nil {
			request.Body.Close()
		}
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(func() { l.release(lane) }) }
	response, err := lane.transport.RoundTrip(request)
	if err != nil {
		release()
		return nil, err
	}
	// a request given up by its context frees its stream as well
	stop := context.AfterFunc(request.Context(), release)
	response.Body = &laneBody{ReadCloser: response.Body, release: func() {
		stop()
		release()
	}}
	return response, nil
}

// acquire counts a request on the first lane with room for it, so that the later ones empty and close.
func (l *http3Lanes) acquire() (*http3Lane, error) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.closed {
		return nil, http3.ErrTransportClosed
	}
	index := slices.IndexFunc(l.lanes, func(lane *http3Lane) bool { return lane.requests < laneRequests })
	var lane *http3Lane
	if index >= 0 {
		lane = l.lanes[index]
	} else {
		lane = &http3Lane{}
		lane.transport = l.newTransport(func(conn *quic.Conn) bool { return l.track(lane, conn) })
		l.lanes = append(l.lanes, lane)
	}
	lane.requests++
	if lane.idle != nil {
		lane.idle.Stop()
		lane.idle = nil
	}
	return lane, nil
}

// release ends the count of a request. The first lane stays, for the pool retires the connection whole.
func (l *http3Lanes) release(lane *http3Lane) {
	l.access.Lock()
	defer l.access.Unlock()
	lane.requests--
	if lane.requests > 0 || lane.closed || l.lanes[0] == lane {
		return
	}
	lane.idle = time.AfterFunc(laneIdleTimeout, func() {
		l.access.Lock()
		if lane.requests > 0 || lane.closed {
			l.access.Unlock()
			return
		}
		lane.closed = true
		l.lanes = slices.DeleteFunc(l.lanes, func(other *http3Lane) bool { return other == lane })
		conns := lane.conns
		lane.conns = nil
		l.access.Unlock()
		lane.close(conns)
	})
}

// track keeps a QUIC connection the lane dialed until it ends; none once the lane is closed.
func (l *http3Lanes) track(lane *http3Lane, conn *quic.Conn) bool {
	l.access.Lock()
	defer l.access.Unlock()
	if lane.closed {
		return false
	}
	if lane.conns == nil {
		lane.conns = make(map[*quic.Conn]struct{})
	}
	lane.conns[conn] = struct{}{}
	context.AfterFunc(conn.Context(), func() {
		l.access.Lock()
		delete(lane.conns, conn)
		l.access.Unlock()
	})
	return true
}

func (l *http3Lanes) Close() error {
	l.access.Lock()
	lanes := l.lanes
	l.lanes = nil
	l.closed = true
	conns := make([]map[*quic.Conn]struct{}, len(lanes))
	for i, lane := range lanes {
		lane.closed = true
		if lane.idle != nil {
			lane.idle.Stop()
		}
		conns[i] = lane.conns
		lane.conns = nil
	}
	l.access.Unlock()
	for i, lane := range lanes {
		lane.close(conns[i])
	}
	return nil
}

// CloseIdleConnections closes the lanes no request is on, with every connection they dialed: quic-go's
// own counts a request only until its response comes, and would close a connection under a download.
func (l *http3Lanes) CloseIdleConnections() {
	l.access.Lock()
	var idle []*http3Lane
	var conns []map[*quic.Conn]struct{}
	l.lanes = slices.DeleteFunc(l.lanes, func(lane *http3Lane) bool {
		if lane.requests > 0 {
			return false
		}
		lane.closed = true
		if lane.idle != nil {
			lane.idle.Stop()
		}
		idle = append(idle, lane)
		conns = append(conns, lane.conns)
		lane.conns = nil
		return true
	})
	l.access.Unlock()
	for i, lane := range idle {
		lane.close(conns[i])
	}
}

// close closes a lane taken out of service and every connection it dialed.
func (lane *http3Lane) close(conns map[*quic.Conn]struct{}) {
	lane.transport.Close()
	for conn := range conns {
		conn.CloseWithError(0, "")
	}
}

// laneBody ends the count of its request when the response body is closed.
type laneBody struct {
	io.ReadCloser
	release func()
}

func (b *laneBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// quic-go's Chrome profile refuses a TLS configuration that verifies the server by itself, as
// one with disable_sni does, or that carries a client certificate.
func chromeParrot(tlsConfig tls.Config) bool {
	std, err := tlsConfig.STDConfig()
	return err == nil && std.VerifyConnection == nil && len(std.Certificates) == 0
}
