package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type directTestOutbound struct {
	adapter.Outbound
}

func (directTestOutbound) Type() string { return C.TypeDirect }

func (directTestOutbound) Tag() string { return "direct" }

func (directTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

type directTestOutboundManager struct {
	adapter.OutboundManager
}

func (directTestOutboundManager) Default() adapter.Outbound { return directTestOutbound{} }

func freeAddress(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().String()
}

// startWithExternalUI starts a controller whose external UI directory is directory and whose
// archive is at archiveURL, and stops it at the end of the test.
func startWithExternalUI(t *testing.T, directory string, archiveURL string) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	server := newListenTestServer(t, freeAddress(t))
	server.ctx = ctx
	server.outbound = directTestOutboundManager{}
	server.externalUI = directory
	server.externalUIDownloadURL = archiveURL
	scope := adapter.NewScope(ctx, log.NewNOPFactory().NewLogger("scope"))
	started := make(chan error, 1)
	go func() { started <- server.Start(adapter.StartStateStarted, scope) }()
	t.Cleanup(func() {
		cancel()
		scope.Close()
	})
	select {
	case err := <-started:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the start waits for the archive of the external UI")
	}
	return server
}

func archiveServer(t *testing.T, files ...string) *httptest.Server {
	content, err := os.ReadFile(writeArchive(t, files...))
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(content)
	}))
	t.Cleanup(server.Close)
	return server
}

// The controller answers while the archive of an empty directory has not come.
func TestExternalUIDownloadDoesNotHoldStart(t *testing.T) {
	release := make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4600000")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(stalled.Close)
	t.Cleanup(func() { close(release) })
	server := startWithExternalUI(t, filepath.Join(t.TempDir(), "ui"), stalled.URL+"/ui.zip")
	require.Eventually(t, func() bool { return answers(server.httpServer.Addr) }, 2*time.Second, 20*time.Millisecond)
}

func TestExternalUIDownloadedAfterStart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ui")
	archive := archiveServer(t, "Yacd-meta-gh-pages/index.html", "Yacd-meta-gh-pages/assets/a.js")
	startWithExternalUI(t, directory, archive.URL+"/ui.zip")
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(directory, "assets", "a.js"))
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, []string{"assets/a.js", "index.html"}, listFiles(t, directory))
}

// The staging directory of an update that did not end is no external UI.
func TestExternalUIDownloadedOverUnfinishedUpdate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ui")
	require.NoError(t, os.MkdirAll(filepath.Join(directory, externalUIStaging), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(directory, externalUIStaging, "index.html"), []byte("partial"), 0o644))
	archive := archiveServer(t, "index.html", "assets/a.js")
	startWithExternalUI(t, directory, archive.URL+"/ui.zip")
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(filepath.Join(directory, "index.html"))
		return err == nil && string(content) == "new index.html"
	}, 5*time.Second, 20*time.Millisecond)
}
