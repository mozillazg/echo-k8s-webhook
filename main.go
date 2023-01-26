package main

import (
	"context"
	"flag"
	"os"

	"github.com/mozillazg/webhookcert/pkg/cert"
	"github.com/mozillazg/webhookcert/pkg/ctlrhelper"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	pkgwebhook "github.com/mozillazg/echo-k8s-webhook/pkg/webhook"
)

const (
	secretName  = "echo-k8s-webhook-server-cert"
	serviceName = "echo-k8s-webhook-service"
	vWCName     = "echo-k8s-webhook"
)

var (
	healthAddr = flag.String("health-addr", ":9090", "The address to which the health endpoint binds")
	port       = flag.Int("port", webhook.DefaultPort, "port for the server")
	certDir    = flag.String("cert-dir", "/certs", "The directory where certs are stored")
	namespace  = flag.String("namespace", "", "namespace of pod")
)

func init() {
	log.SetLogger(zap.New())
}

var entryLog = log.Log.WithName("entrypoint")

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *namespace == "" {
		*namespace = os.Getenv("POD_NAMESPACE")
	}
	entryLog.Info("setting up manager")
	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		LeaderElection:         false,
		Port:                   *port,
		CertDir:                *certDir,
		HealthProbeBindAddress: *healthAddr,
		MetricsBindAddress:     "0",
	})
	if err != nil {
		entryLog.Error(err, "unable to set up overall controller manager")
		os.Exit(1)
	}

	entryLog.Info("setting up webhook")
	ctx := signals.SetupSignalHandler()
	errC := make(chan error, 2)

	setupWebhook(ctx, mgr, errC)
	go func() {
		entryLog.Info("starting manager")
		if err := mgr.Start(ctx); err != nil {
			entryLog.Error(err, "unable to run manager")
			errC <- err
		}
	}()

	select {
	case <-errC:
		os.Exit(1)
	case <-ctx.Done():
	}
}

func setupWebhook(ctx context.Context, mgr manager.Manager, errC chan<- error) {
	opt := ctlrhelper.Option{
		Namespace:   *namespace,
		SecretName:  secretName,
		ServiceName: serviceName,
		CertDir:     *certDir,
		Webhooks: []cert.WebhookInfo{
			{
				Type: cert.ValidatingV1,
				Name: vWCName,
			},
		},
		WebhookServerPort: *port,
	}
	h, err := ctlrhelper.NewNewWebhookHelper(opt)
	if err != nil {
		entryLog.Error(err, "unable creates a new WebhookHelper")
		errC <- err
		return
	}
	handler := pkgwebhook.NewEchoWebhook(mgr.GetClient(), pkgwebhook.NewLogRecorder())

	h.Setup(ctx, mgr, func(s *webhook.Server) {
		s.Register("/webhook", &webhook.Admission{Handler: handler})
	}, errC)
}
