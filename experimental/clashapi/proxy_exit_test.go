package clashapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type exitTraceCertificateStore struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (s *exitTraceCertificateStore) Pool() *x509.CertPool { return s.pool }

// Dials a trace server address to the local server standing in for it, never answers the
// stalled ones and refuses the rest.
type exitTraceOutbound struct {
	*linkAPIOutbound
	servers map[netip.Addr]string
	stalled map[netip.Addr]bool
}

func (o *exitTraceOutbound) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	if o.stalled[destination.Addr] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	address, loaded := o.servers[destination.Addr]
	if !loaded || destination.Port != 443 {
		return nil, errors.New("connection refused")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", address)
}

func (o *exitTraceOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no UDP")
}

type exitTraceGroup struct {
	*exitTraceOutbound
	tag    string
	member string
}

func (g *exitTraceGroup) Tag() string   { return g.tag }
func (g *exitTraceGroup) Now() string   { return g.member }
func (g *exitTraceGroup) All() []string { return []string{g.member} }

type exitTraceBench struct {
	t           *testing.T
	certificate tls.Certificate
	pool        *x509.CertPool
}

// The certificate names the trace servers by address, as Cloudflare's does.
func newExitTraceBench(t *testing.T) *exitTraceBench {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "one.one.one.one"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, address := range slices.Concat(exitTraceServersIPv4, exitTraceServersIPv6) {
		template.IPAddresses = append(template.IPAddresses, net.IP(address.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &exitTraceBench{
		t:           t,
		certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pool:        pool,
	}
}

// A trace server answering as Cloudflare would for a request from address; it checks the request
// is the one the core sends to the trace server it stands in for.
func (b *exitTraceBench) traceServer(server netip.Addr, address, country string) string {
	host := server.String()
	if server.Is6() {
		host = "[" + host + "]"
	}
	traceServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/cdn-cgi/trace" || r.Host != host {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "fl=1f1\nh=%s\nip=%s\nts=1792504042.000\nvisit_scheme=https\nuag=Go-http-client/1.1\ncolo=FRA\nhttp=http/1.1\nloc=%s\ntls=TLSv1.3\nsni=off\nwarp=off\n", host, address, country)
	}))
	traceServer.TLS = &tls.Config{Certificates: []tls.Certificate{b.certificate}}
	traceServer.StartTLS()
	b.t.Cleanup(traceServer.Close)
	return traceServer.Listener.Addr().String()
}

func (b *exitTraceBench) server(outbounds ...adapter.Outbound) *Server {
	ctx := service.ContextWith[adapter.CertificateStore](context.Background(), &exitTraceCertificateStore{pool: b.pool})
	clashServer, err := NewServer(clashTestContext(ctx), log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		b.t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = &linkAPIOutboundManager{outbounds: outbounds}
	return server
}

func newExitTraceOutbound(tag string) *exitTraceOutbound {
	return &exitTraceOutbound{
		linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil)},
		servers:         map[netip.Addr]string{},
		stalled:         map[netip.Addr]bool{},
	}
}

func requestExit(t *testing.T, server *Server, path string) (*httptest.ResponseRecorder, exitReport) {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	var report exitReport
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
	}
	return response, report
}

func errorMessage(t *testing.T, response *httptest.ResponseRecorder) string {
	var payload HTTPError
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Message
}

// A section is asked through its selector, and the report names the node the selection reached.
func TestProxyExitReportsEachFamilyOfTheSelectedNode(t *testing.T) {
	bench := newExitTraceBench(t)
	node := newExitTraceOutbound("proxy/Node A")
	node.servers[exitTraceServersIPv4[0]] = bench.traceServer(exitTraceServersIPv4[0], "203.0.113.7", "NL")
	node.servers[exitTraceServersIPv6[0]] = bench.traceServer(exitTraceServersIPv6[0], "2001:db8::7", "NL")
	section := &exitTraceGroup{exitTraceOutbound: node, tag: "proxy-out", member: "proxy/Node A"}

	response, report := requestExit(t, bench.server(section, node), "/proxies/proxy-out/exit?timeout=5000")
	if response.Code != http.StatusOK {
		t.Fatalf("exit request returned %d: %s", response.Code, response.Body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected Cache-Control: %q", response.Header().Get("Cache-Control"))
	}
	expected := exitReport{
		Outbound: "proxy/Node A",
		IPv4:     exitAddress{Address: "203.0.113.7", Country: "NL"},
		IPv6:     exitAddress{Address: "2001:db8::7", Country: "NL"},
	}
	if report != expected {
		t.Fatalf("unexpected report: %+v", report)
	}
}

// A first address dropped on the path must not cost the family its answer, nor the whole timeout.
func TestProxyExitAnswersFromTheSecondServerOfAFamily(t *testing.T) {
	bench := newExitTraceBench(t)
	node := newExitTraceOutbound("proxy/Node A")
	node.stalled[exitTraceServersIPv4[0]] = true
	node.servers[exitTraceServersIPv4[1]] = bench.traceServer(exitTraceServersIPv4[1], "203.0.113.8", "DE")

	start := time.Now()
	response, report := requestExit(t, bench.server(node), "/proxies/proxy%2FNode%20A/exit?timeout=5000")
	if response.Code != http.StatusOK {
		t.Fatalf("exit request returned %d: %s", response.Code, response.Body)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the second server answered only after %v", elapsed)
	}
	expected := exitReport{
		Outbound: "proxy/Node A",
		IPv4:     exitAddress{Address: "203.0.113.8", Country: "DE"},
		IPv6:     exitAddress{Error: "connection refused"},
	}
	if report != expected {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestProxyExitFailsWhenNoFamilyAnswers(t *testing.T) {
	bench := newExitTraceBench(t)
	refusing := newExitTraceOutbound("proxy/Refusing")
	stalling := newExitTraceOutbound("proxy/Stalling")
	for _, address := range slices.Concat(exitTraceServersIPv4, exitTraceServersIPv6) {
		stalling.stalled[address] = true
	}
	server := bench.server(refusing, stalling)

	response, _ := requestExit(t, server, "/proxies/proxy%2FRefusing/exit?timeout=5000")
	if response.Code != http.StatusServiceUnavailable || errorMessage(t, response) != "connection refused" {
		t.Fatalf("a refusing node returned %d: %s", response.Code, response.Body)
	}
	response, _ = requestExit(t, server, "/proxies/proxy%2FStalling/exit?timeout=100")
	if response.Code != http.StatusGatewayTimeout || errorMessage(t, response) != ErrRequestTimeout.Message {
		t.Fatalf("a silent node returned %d: %s", response.Code, response.Body)
	}
	for _, timeout := range []string{"", "0", "-1", "abc"} {
		response, _ = requestExit(t, server, "/proxies/proxy%2FRefusing/exit?timeout="+timeout)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("timeout %q returned %d", timeout, response.Code)
		}
	}
}

func TestParseExitTrace(t *testing.T) {
	address, err := parseExitTrace("fl=903f79\nh=1.1.1.1\nip=198.51.100.4\nts=1792504042.000\ncolo=DME\nloc=RU\nwarp=off\n")
	if err != nil || address != (exitAddress{Address: "198.51.100.4", Country: "RU"}) {
		t.Fatalf("unexpected parse: %+v, %v", address, err)
	}
	for _, body := range []string{"", "loc=RU\n", "ip=not-an-address\nloc=RU\n", "<html>blocked</html>"} {
		if _, err = parseExitTrace(body); err == nil {
			t.Fatalf("parsed an address out of %q", body)
		}
	}
}
