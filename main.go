// Copyright (c) 2022-2024 Cisco and/or its affiliates.
//
// Copyright (c) 2024 OpenInfra Foundation Europe. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.fd.io/govpp/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/vpphelper"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/clientinfo"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/heal"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	kernel_sdk "github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/retry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/swapip"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/registry/chains/proxydns"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
	"github.com/networkservicemesh/sdk/pkg/tools/pprofutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"

	"github.com/networkservicemesh/cmd-nsc-simple-docker/internal/spireconfig"
	"github.com/networkservicemesh/cmd-nsc-simple-docker/vppinit"
	kernelheal "github.com/networkservicemesh/sdk-kernel/pkg/kernel/tools/heal"
	vppforwarder "github.com/networkservicemesh/sdk-vpp/pkg/networkservice/chains/forwarder"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/kernel"
)

const (
	forwarderSockName     = "forwarder.sock"
	registryProxySockName = "registry.proxy.sock"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name             string        `default:"docker-nsc" desc:"Name of docker client"`
	RequestTimeout   time.Duration `default:"15s" desc:"timeout to request NSE" split_words:"true"`
	ConnectTo        url.URL       `default:"tcp://k8s.nsm" desc:"url to connect to" split_words:"true"`
	DialTimeout      time.Duration `default:"5s" desc:"timeout to dial" split_words:"true"`
	MaxTokenLifetime time.Duration `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	TunnelIP         net.IP        `desc:"IP to use for tunnels" split_words:"true"`

	Labels          []string  `default:"" desc:"A list of client labels with format key1=val1,key2=val2, will be used a primary list for network services" split_words:"true"`
	NetworkServices []url.URL `default:"" desc:"A list of Network Service Requests" split_words:"true"`

	FederatesWith string `default:"k8s.nsm" desc:"Name of the federated domain" split_words:"true"`
	TrustDomain   string `default:"docker.nsm" desc:"Name of the trust domain" split_words:"true"`
	LogLevel      string `default:"INFO" desc:"Log level" split_words:"true"`

	PprofEnabled  bool   `default:"false" desc:"is pprof enabled" split_words:"true"`
	PprofListenOn string `default:"localhost:6060" desc:"pprof URL to ListenAndServe" split_words:"true"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	return nil
}

//
// This application consists of the following parts:
//
//    ┌─────────┐      ┌───────────────┐
//    │         │      │               │   Request()
//    │   NSC   ├─────►│   Local FWD   ├───────────────────► [k8s] nsmgr-proxy
//    │         │      │               │
//    └─────────┘      └──────┬────────┘
//                            │discover
//                            │
//                     ┌──────▼────────┐
//                     │               │    Find()
//                     │Proxy  Registry├───────────────────► [k8s] registry
//                     │               │
//                     └───────────────┘
// NSC - sends a Request to the local Forwarder
// Local Forwarder - finds an NSE (using proxy registry), creates local and remote mechanisms
// Proxy Registry - handles a request by domain
//

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}

	starttime := time.Now()
	// enumerating phases
	log.FromContext(ctx).Infof("there are 7 phases which will be executed followed by a success message:")
	log.FromContext(ctx).Infof("the phases include:")
	log.FromContext(ctx).Infof("1: get config from environment")
	log.FromContext(ctx).Infof("2: run vpp and get a connection to it")
	log.FromContext(ctx).Infof("3: start spire-server and spire-agent")
	log.FromContext(ctx).Infof("4: retrieving svid, check spire agent logs if this is the last line you see")
	log.FromContext(ctx).Infof("5: create local forwarder")
	log.FromContext(ctx).Infof("6: create nsc and do request to the forwarder")
	log.FromContext(ctx).Infof("a final success message with start time duration")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := new(Config)
	if err := config.Process(); err != nil {
		log.FromContext(ctx).Fatal(err.Error())
	}
	log.FromContext(ctx).Infof("Config: %#v", config)

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		log.FromContext(ctx).Fatalf("invalid log level %s", config.LogLevel)
	}
	logrus.SetLevel(level)
	logruslogger.SetupLevelChangeOnSignal(ctx, map[os.Signal]logrus.Level{
		syscall.SIGUSR1: logrus.TraceLevel,
		syscall.SIGUSR2: level,
	})

	// Configure pprof
	if config.PprofEnabled {
		go pprofutils.ListenAndServe(ctx, config.PprofListenOn)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 2: run vpp and get a connection to it")
	// ********************************************************************************
	vppConn, vppErrCh := vpphelper.StartAndDialContext(ctx)
	exitOnErr(ctx, cancel, vppErrCh)

	defer func() {
		cancel()
		<-vppErrCh
	}()
	config.TunnelIP = vppinit.Must(vppinit.LinkToAfPacket(ctx, vppConn, config.TunnelIP))

	// ********************************************************************************
	log.FromContext(ctx).Info("executing phase 3: start spire-server and spire-agent")
	// ********************************************************************************
	spireRoot, err := os.MkdirTemp("", "spire")
	if err != nil {
		log.FromContext(ctx).Fatalf("error while creating spire root: %+v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		log.FromContext(ctx).Fatalf("error while getting the app name: %+v", err)
	}
	spireChannel := spire.Start(
		spire.WithContext(ctx),
		spire.WithAgentID(fmt.Sprintf("spiffe://%s/agent", config.TrustDomain)),
		spire.WithAgentConfig(fmt.Sprintf(spireconfig.SpireAgentConfContents, spireRoot, config.TrustDomain)),
		spire.WithServerConfig(fmt.Sprintf(spireconfig.SpireServerConfContents, spireRoot, config.TrustDomain, config.FederatesWith, config.ConnectTo.Hostname())),
		spire.WithRoot(spireRoot),
		spire.WithFederatedEntry(fmt.Sprintf("spiffe://%s/%s", config.TrustDomain, filepath.Base(executable)),
			fmt.Sprintf("unix:path:%s", executable),
			fmt.Sprintf("spiffe://%s", config.FederatesWith),
		),
	)
	if len(spireChannel) != 0 {
		log.FromContext(ctx).Fatal(<-spireChannel)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 4: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.FromContext(ctx).Fatalf("error getting x509 source: %+v", err)
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		log.FromContext(ctx).Fatalf("error getting x509 svid: %+v", err)
	}
	log.FromContext(ctx).Infof("SVID: %q", svid.ID)

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 5: create local forwarder")
	// ********************************************************************************

	tlsClientConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsClientConfig.MinVersion = tls.VersionTLS12
	tlsServerConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsServerConfig.MinVersion = tls.VersionTLS12

	clientOptions := append(tracing.WithTracingDial(),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime))),
		),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsClientConfig,
				),
			),
		),
	)

	listenOn := createForwarder(
		ctx,
		cancel,
		config,
		vppConn,
		source,
		tlsServerConfig,
		clientOptions...)
	log.FromContext(ctx).Infof("grpc server started: %v", listenOn.String())

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 6: create nsc and do request to the forwarder")
	// ********************************************************************************

	// We construct a client here and send Request to itself. Thus, we create a local nsm interface.
	dockerClient := createClient(ctx, listenOn, config, clientOptions...)

	for i := 0; i < len(config.NetworkServices); i++ {
		u := (*nsurl.NSURL)(&config.NetworkServices[i])
		id := fmt.Sprintf("%s-%d", config.Name, i)

		// Construct a request
		request := &networkservice.NetworkServiceRequest{
			Connection: &networkservice.Connection{
				Id:             id,
				NetworkService: u.NetworkService(),
				Labels:         u.Labels(),
			},
			MechanismPreferences: []*networkservice.Mechanism{
				u.Mechanism(),
			},
		}
		var resp *networkservice.Connection
		resp, err = dockerClient.Request(ctx, request)
		if err != nil {
			log.FromContext(ctx).Errorf("request itself: %v", err)
		}
		defer func() {
			closeCtx, cancelClose := context.WithTimeout(ctx, config.RequestTimeout)
			defer cancelClose()
			_, _ = dockerClient.Close(closeCtx, resp)
		}()
	}

	log.FromContext(ctx).Infof("Startup completed in %v", time.Since(starttime))

	// wait for server to exit
	<-ctx.Done()
	<-vppErrCh
}

func createForwarder(ctx context.Context, cancel context.CancelFunc, config *Config, vppConn api.Connection, source *workloadapi.X509Source, tlsServerConfig *tls.Config, dialOptions ...grpc.DialOption) *url.URL {
	gRPCOptions := append(
		tracing.WithTracing(),
		grpc.Creds(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsServerConfig,
				),
			),
		),
	)

	/* Create registry-proxy */
	serverRegistryProxy := grpc.NewServer(gRPCOptions...)
	proxydns.NewServer(ctx, spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime), net.DefaultResolver, proxydns.WithDialOptions(dialOptions...)).Register(serverRegistryProxy)

	listenOnRegistryProxy := &url.URL{Scheme: "unix", Path: filepath.Join(os.TempDir(), registryProxySockName)}
	srvErrChReg := grpcutils.ListenAndServe(ctx, listenOnRegistryProxy, serverRegistryProxy)
	exitOnErr(ctx, cancel, srvErrChReg)

	/* Create forwarder */
	var swapIPCh = make(chan map[string]string, 1)
	swapIPCh <- map[string]string{config.TunnelIP.String(): config.TunnelIP.String()}
	close(swapIPCh)

	server := grpc.NewServer(gRPCOptions...)
	vppforwarder.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		vppConn,
		config.TunnelIP,
		vppforwarder.WithName(config.Name+"-forwarder"),
		vppforwarder.WithAuthorizeServer(authorize.NewServer()),
		vppforwarder.WithClientURL(listenOnRegistryProxy),
		vppforwarder.WithDialTimeout(config.DialTimeout),
		vppforwarder.WithClientAdditionalFunctionality(swapip.NewClient(swapIPCh)),
		vppforwarder.WithDialOptions(dialOptions...)).Register(server)

	listenOn := &url.URL{Scheme: "unix", Path: filepath.Join(os.TempDir(), forwarderSockName)}
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)

	return listenOn
}

func createClient(ctx context.Context, clientURL *url.URL, config *Config, dialOptions ...grpc.DialOption) networkservice.NetworkServiceClient {
	nsmClient := client.NewClient(ctx,
		client.WithClientURL(clientURL),
		client.WithName(config.Name),
		client.WithAuthorizeClient(authorize.NewClient()),
		client.WithHealClient(
			heal.NewClient(
				ctx,
				heal.WithLivenessCheck(kernelheal.KernelLivenessCheck),
			),
		),
		client.WithAdditionalFunctionality(
			clientinfo.NewClient(),
			mechanisms.NewClient(map[string]networkservice.NetworkServiceClient{
				kernel.MECHANISM: chain.NewNetworkServiceClient(kernel_sdk.NewClient()),
			}),
			sendfd.NewClient(),
		),
		client.WithDialTimeout(config.DialTimeout),
		client.WithDialOptions(dialOptions...),
	)

	return retry.NewClient(nsmClient, retry.WithTryTimeout(config.RequestTimeout))
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}
