package warp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	profileRetryInitialDelay = 5 * time.Second
	profileRetryMaxDelay     = time.Minute
)

var _ adapter.OutboundWithMultiplex = (*Endpoint)(nil)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WARPEndpointOptions](registry, C.TypeWARP, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx          context.Context
	logger       log.ContextLogger
	options      option.WARPEndpointOptions
	access       sync.RWMutex
	endpoint     adapter.Endpoint
	startHandler func(scope *adapter.Scope)
	cancel       context.CancelFunc

	// await closes once the first attempt to bring the endpoint up ends, done
	// once the attempts, retries included, stop.
	await     chan struct{}
	awaitOnce sync.Once
	done      chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WARPEndpointOptions) (adapter.Endpoint, error) {
	profileFields := 0
	for _, value := range []string{options.Profile.ID, options.Profile.AuthToken, options.Profile.PrivateKey} {
		if value != "" {
			profileFields++
		}
	}
	if profileFields != 0 && profileFields != 3 {
		return nil, E.New("WARP profile id, auth_token, and private_key must be provided together")
	}
	ctx, cancel := context.WithCancel(ctx)
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	endpoint := &Endpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:     ctx,
		logger:  logger,
		cancel:  cancel,
		options: options,
		await:   make(chan struct{}),
		done:    make(chan struct{}),
	}
	endpoint.startHandler = func(scope *adapter.Scope) {
		defer endpoint.release()
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *Config
		var err error
		cacheKey := warpCacheKey(tag, options.Profile)
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadWARPConfig(cacheKey)
			if savedProfile != nil {
				if unmarshalErr := json.Unmarshal(savedProfile.Content, &config); unmarshalErr != nil {
					logger.WarnContext(ctx, "discarding unreadable cached WARP profile: ", unmarshalErr)
					config = nil
				} else if validationErr := validateConfig(config); validationErr != nil {
					logger.WarnContext(ctx, "discarding invalid cached WARP profile: ", validationErr)
					config = nil
				} else if options.Profile.PrivateKey != "" && config.PrivateKey != options.Profile.PrivateKey {
					logger.WarnContext(ctx, "discarding cached WARP profile with a different private key")
					config = nil
				}
			}
		}
		if config == nil {
			config = endpoint.fetchConfig(logger, endpoint.createConfig)
			if config == nil {
				return
			}
			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				if err = cacheFile.SaveWARPConfig(cacheKey, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				}); err != nil {
					logger.ErrorContext(ctx, E.Cause(err, "save WARP profile cache"))
				}
			}
		}
		peer := config.Peers[0]
		peerAddress := warpPeerAddress(peer.Endpoint.Host)
		peerPort := uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))])
		if options.Address != "" {
			peerAddress = options.Address
		}
		if options.Port != 0 {
			peerPort = options.Port
		}
		wireguardEndpoint, err := wireguard.NewEndpoint(
			ctx,
			router,
			logger,
			tag,
			option.WireGuardEndpointOptions{
				// Cloudflare answers plain WireGuard, so the WARP endpoint carries
				// the same one-sided obfuscation class and passes it straight on.
				Amnezia: options.Amnezia,
				WireGuardCommonOptions: option.WireGuardCommonOptions{
					System:        options.System,
					Name:          options.Name,
					ListenPort:    options.ListenPort,
					UDPTimeout:    options.UDPTimeout,
					Workers:       options.Workers,
					DialerOptions: options.DialerOptions,

					Address: badoption.Listable[netip.Prefix]{
						netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
						netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
					},
					PrivateKey: config.PrivateKey,
					Peers: []option.WireGuardPeer{
						{
							Address:   peerAddress,
							Port:      peerPort,
							PublicKey: peer.PublicKey,
							AllowedIPs: badoption.Listable[netip.Prefix]{
								netip.MustParsePrefix("0.0.0.0/0"),
								netip.MustParsePrefix("::/0"),
							},
							PersistentKeepaliveInterval: options.PersistentKeepaliveInterval,
						},
					},
					MTU: 1280,
				},
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart} {
			err = scope.Start("endpoint/"+wireguardEndpoint.Type()+"["+wireguardEndpoint.Tag()+"]", wireguardEndpoint, stage)
			if err != nil {
				_ = scope.Close()
				logger.ErrorContext(ctx, err)
				return
			}
		}
		endpoint.access.Lock()
		endpoint.endpoint = wireguardEndpoint
		endpoint.access.Unlock()
	}
	return endpoint, nil
}

// fetchConfig asks Cloudflare until it gets a valid profile, or returns nil
// once the endpoint closes. Dials wait only for the first attempt.
func (w *Endpoint) fetchConfig(logger log.ContextLogger, fetch func() (*Config, error)) *Config {
	delay := profileRetryInitialDelay
	for {
		config, err := fetch()
		if err == nil {
			err = validateConfig(config)
			if err != nil {
				err = E.Cause(err, "invalid WARP profile")
			}
		}
		if err == nil {
			return config
		}
		if w.ctx.Err() != nil {
			return nil
		}
		logger.ErrorContext(w.ctx, E.Cause(err, "fetch WARP profile, retrying in ", delay))
		w.release()
		select {
		case <-w.ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(delay*2, profileRetryMaxDelay)
	}
}

func (w *Endpoint) release() {
	w.awaitOnce.Do(func() { close(w.await) })
}

func warpCacheKey(tag string, profile option.CloudflareProfile) string {
	if profile.ID == "" && profile.AuthToken == "" && profile.PrivateKey == "" && profile.LicenseKey == "" {
		return tag
	}
	hash := sha256.Sum256([]byte(profile.ID + "\x00" + profile.AuthToken + "\x00" + profile.PrivateKey + "\x00" + profile.LicenseKey))
	return tag + ":" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func warpPeerAddress(host string) string {
	host = strings.TrimSpace(host)
	if address, _, err := net.SplitHostPort(host); err == nil {
		return address
	}
	return strings.Trim(host, "[]")
}

func validateConfig(config *Config) error {
	if config == nil {
		return E.New("profile response is empty")
	}
	if _, err := wgtypes.ParseKey(config.PrivateKey); err != nil {
		return E.Cause(err, "invalid private key")
	}
	v4, err := netip.ParseAddr(strings.TrimSpace(config.Interface.Addresses.V4))
	if err != nil || !v4.Is4() {
		return E.New("invalid IPv4 interface address")
	}
	v6, err := netip.ParseAddr(strings.TrimSpace(config.Interface.Addresses.V6))
	if err != nil || !v6.Is6() {
		return E.New("invalid IPv6 interface address")
	}
	if len(config.Peers) == 0 {
		return E.New("profile has no peers")
	}
	peer := config.Peers[0]
	if _, err := wgtypes.ParseKey(strings.TrimSpace(peer.PublicKey)); err != nil {
		return E.Cause(err, "invalid profile peer public key")
	}
	if strings.TrimSpace(peer.Endpoint.Host) == "" {
		return E.New("profile peer has no endpoint host")
	}
	if len(peer.Endpoint.Ports) == 0 {
		return E.New("profile peer has no endpoint ports")
	}
	for _, port := range peer.Endpoint.Ports {
		if port < 1 || port > 65535 {
			return E.New("profile peer has invalid endpoint port ", port)
		}
	}
	return nil
}

func (w *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	endpointScope := adapter.NewScope(w.ctx, w.logger)
	scope.Add(func() error {
		w.cancel()
		<-w.done
		return endpointScope.Close()
	})
	go func() {
		defer close(w.done)
		w.startHandler(endpointScope)
	}()
	return nil
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	endpoint, err := w.initializedEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	endpoint, err := w.initializedEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return endpoint.ListenPacket(ctx, destination)
}

func (w *Endpoint) MultiplexEnabled() bool {
	return true
}

func (w *Endpoint) initializedEndpoint(ctx context.Context) (adapter.Endpoint, error) {
	select {
	case <-w.await:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	w.access.RLock()
	defer w.access.RUnlock()
	if w.endpoint == nil {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint, nil
}

func (w *Endpoint) createConfig() (*Config, error) {
	opts := make([]cloudflare.CloudflareApiOption, 0, 1)
	if w.options.Profile.Detour != "" {
		detour, ok := service.FromContext[adapter.OutboundManager](w.ctx).Outbound(w.options.Profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", w.options.Profile.Detour)
		}
		opts = append(opts, cloudflare.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	var privateKey wgtypes.Key
	var err error
	if w.options.Profile.PrivateKey != "" {
		privateKey, err = wgtypes.ParseKey(w.options.Profile.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
	}
	api := cloudflare.NewCloudflareApi(opts...)
	var profile *cloudflare.CloudflareProfile
	if w.options.Profile.AuthToken != "" && w.options.Profile.ID != "" {
		profile, err = api.GetProfile(w.ctx, w.options.Profile.AuthToken, w.options.Profile.ID)
		if err != nil {
			return nil, err
		}
	} else {
		profile, err = api.CreateProfile(w.ctx, privateKey.PublicKey().String())
		if err != nil {
			return nil, err
		}
	}
	if w.options.Profile.LicenseKey != "" && profile.Account.License != w.options.Profile.LicenseKey {
		if _, err = api.UpdateAccount(w.ctx, profile.Token, profile.ID, w.options.Profile.LicenseKey); err != nil {
			return nil, E.New("failed to apply license key: ", err)
		}
	}
	return &Config{
		PrivateKey: privateKey.String(),
		Interface:  profile.Config.Interface,
		Peers:      profile.Config.Peers,
	}, nil
}
