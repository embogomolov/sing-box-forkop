package clashapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"github.com/go-chi/render"
)

// Cloudflare's trace page on the addresses of 1.1.1.1 names the address a request came from
// (ip=) and its country (loc=); a literal fixes the family and needs no DNS through the outbound.
var (
	exitTraceServersIPv4 = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	exitTraceServersIPv6 = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}
)

const exitTraceBodyLimit = 4096

type exitAddress struct {
	Address string `json:"address,omitempty"`
	Country string `json:"country,omitempty"`
	Error   string `json:"error,omitempty"`
}

type exitReport struct {
	Outbound string      `json:"outbound"`
	IPv4     exitAddress `json:"ipv4"`
	IPv6     exitAddress `json:"ipv6"`
}

func getProxyExit(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		timeout, err := strconv.ParseInt(r.URL.Query().Get("timeout"), 10, 32)
		if err != nil || timeout <= 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		ctx, cancel := context.WithTimeout(server.ctx, time.Millisecond*time.Duration(timeout))
		defer cancel()
		defer context.AfterFunc(r.Context(), cancel)()

		report := exitReport{Outbound: group.RealTag(server.outbound, proxy)}
		var errIPv4, errIPv6 error
		var wg sync.WaitGroup
		wg.Go(func() { report.IPv4, errIPv4 = lookupExitAddress(ctx, proxy, exitTraceServersIPv4) })
		wg.Go(func() { report.IPv6, errIPv6 = lookupExitAddress(ctx, proxy, exitTraceServersIPv6) })
		wg.Wait()

		switch {
		case errIPv4 == nil || errIPv6 == nil:
			report.IPv4.Error = exitErrorMessage(errIPv4)
			report.IPv6.Error = exitErrorMessage(errIPv6)
			render.JSON(w, r, report)
		case errors.Is(errIPv4, context.DeadlineExceeded):
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
		default:
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(errIPv4.Error()))
		}
	}
}

func exitErrorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return ErrRequestTimeout.Message
	default:
		return err.Error()
	}
}

// The servers are raced, so one dropped on the path does not cost the family its answer; when
// none answers, the error is the first server's.
func lookupExitAddress(ctx context.Context, detour N.Dialer, servers []netip.Addr) (exitAddress, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		index   int
		address exitAddress
		err     error
	}
	outcomes := make(chan outcome, len(servers))
	for index, server := range servers {
		go func() {
			address, err := traceExitAddress(ctx, detour, server)
			outcomes <- outcome{index, address, err}
		}()
	}
	failures := make([]error, len(servers))
	for range servers {
		result := <-outcomes
		if result.err == nil {
			return result.address, nil
		}
		failures[result.index] = result.err
	}
	return exitAddress{}, failures[0]
}

func traceExitAddress(ctx context.Context, detour N.Dialer, server netip.Addr) (exitAddress, error) {
	destination := M.SocksaddrFrom(server, 443)
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return detour.DialContext(ctx, N.NetworkTCP, destination)
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	host := server.String()
	if server.Is6() {
		host = "[" + host + "]"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return exitAddress{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return exitAddress{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return exitAddress{}, E.New("unexpected HTTP status: ", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, exitTraceBodyLimit))
	if err != nil {
		return exitAddress{}, err
	}
	return parseExitTrace(string(body))
}

func parseExitTrace(body string) (exitAddress, error) {
	var (
		address netip.Addr
		country string
	)
	for line := range strings.Lines(body) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "ip":
			address, _ = netip.ParseAddr(value)
		case "loc":
			country = value
		}
	}
	if !address.IsValid() {
		return exitAddress{}, E.New("no address in the trace response")
	}
	return exitAddress{Address: address.String(), Country: country}, nil
}
