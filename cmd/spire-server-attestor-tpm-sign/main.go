package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	Socket    string   `hcl:"socket"`
	URLs      []string `hcl:"urls"`
	Frequency string   `hcl:"frequency"`
}

type Plugin struct {
	bundlepublisherv1.UnimplementedBundlePublisherServer
	configv1.UnimplementedConfigServer
	configMtx  sync.RWMutex
	config     *Config
	bundle     *types.Bundle
	bundleMtx  sync.RWMutex
	logger     hclog.Logger
	lastUpdate time.Time
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	frequency, err := time.ParseDuration(config.Frequency)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse frequency")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) && time.Now().Before(p.lastUpdate.Add(frequency)) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	bundleFormat, _ := bundleformat.FromString("pem")

	formatter := bundleformat.NewFormatter(req.Bundle)
	bundleBytes, err := formatter.Format(bundleFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err.Error())
	}

	p.logger.Debug(fmt.Sprintf("Got bundle in plugin: %s", config))
	token, err := signTrustBundle(config.Socket, config.URLs, strings.NewReader(string(bundleBytes)))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not sign bundle: %v", err.Error())
	}
	p.logger.Debug("Got bundle in plugin %s", token)

	err = publishTrustBundle(config.Socket, token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not publish bundle: %v", err.Error())
	}

	p.setBundle(req.Bundle)
	p.lastUpdate = time.Now()

	p.logger.Debug(fmt.Sprintf("Next update due to timeout sometime after %s", p.lastUpdate.Add(frequency).Add(30*time.Second)))

	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if config.Socket == "" {
		config.Socket = "/var/run/spire/server-attestor-tpm/signer-unix.sock"
	}
	if config.Frequency == "" {
		config.Frequency = "5m"
	}
	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	return p.bundle
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func signTrustBundle(socket string, addrs []string, trustBundle io.Reader) (token string, err error) {
	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}

	ctx := context.Background()

	ureq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/sign", trustBundle)
	if err != nil {
		return "", err
	}

	uresp, err := c.Do(ureq)
	if err != nil {
		return "", err
	}
	sbody, err := io.ReadAll(uresp.Body)
	if err != nil {
		return "", err
	}
	defer uresp.Body.Close()

	for _, addr := range addrs {
		c := http.Client{}

		ureq, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewBuffer(sbody))
		if err != nil {
			return "", err
		}

		uresp, err := c.Do(ureq)
		if err != nil {
			return "", err
		}
		nbody, err := io.ReadAll(uresp.Body)
		if err != nil {
			return "", err
		}
		defer uresp.Body.Close()
		sbody = nbody
	}
	return string(sbody), nil
}

func publishTrustBundle(socket string, token string) (err error) {
	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}

	ctx := context.Background()

	ureq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/publish", bytes.NewBuffer([]byte(token)))
	if err != nil {
		return err
	}

	uresp, err := c.Do(ureq)
	if err != nil {
		return err
	}
	defer uresp.Body.Close()
	return nil
}

func main() {
	if os.Getenv("BundlePublisher") != "" {
		plugin := new(Plugin)
		pluginmain.Serve(
			bundlepublisherv1.BundlePublisherPluginServer(plugin),
			configv1.ConfigServiceServer(plugin),
		)
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage:", os.Args[0], "/path/to/unix.sock urls...")
		os.Exit(1)
	}

	socket := os.Args[1]
	addrs := os.Args[2:]

	token, err := signTrustBundle(socket, addrs, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	err = publishTrustBundle(socket, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("%s", token)
}
