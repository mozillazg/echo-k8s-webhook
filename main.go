package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/mozillazg/webhookcert/pkg/cert"
	"github.com/mozillazg/webhookcert/pkg/ctlrhelper"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
	secretName     = "echo-k8s-webhook-server-cert"
	serviceName    = "echo-k8s-webhook-service"
	caName         = "echo-k8s-webhook-ca"
	caOrganization = "echo-k8s-webhook"
	vWCName        = "echo-k8s-webhook"
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
	setupWebhook(ctx, mgr)

	entryLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		entryLog.Error(err, "unable to run manager")
		os.Exit(1)
	}
}

func setupWebhook(ctx context.Context, mgr manager.Manager) {
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
	}
	h := ctlrhelper.NewNewWebhookHelperOrDie(opt)
	handler := pkgwebhook.NewEchoWebhook(mgr.GetClient(), pkgwebhook.NewLogRecorder())

	h.Setup(ctx, mgr, func(s *webhook.Server) {
		s.Register("/webhook", &webhook.Admission{Handler: handler})
	})
}

func ensureCertReady(dnsName string, setupFinished chan struct{}, timeout time.Duration) *cert.WebhookCert {
	kubeclient := kubernetes.NewForConfigOrDie(config.GetConfigOrDie())
	dyclient := dynamic.NewForConfigOrDie(config.GetConfigOrDie())
	webhooks := []cert.WebhookInfo{
		{
			Type: cert.ValidatingV1,
			Name: vWCName,
		},
	}
	webhookcert := cert.NewWebhookCert(cert.CertOption{
		CAName:        caName,
		Organizations: []string{caOrganization},
		Hosts:         []string{dnsName},
		CommonName:    dnsName,
		CertDir:       *certDir,
		SecretInfo: cert.SecretInfo{
			Name:      secretName,
			Namespace: *namespace,
		},
	}, webhooks, kubeclient, dyclient)

	ctx := context.Background()
	go func() {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := webhookcert.EnsureCertReady(ctxWithTimeout); err != nil {
			klog.Fatalf("ensure cert ready failed: %+v", err)
		}
		close(setupFinished)
		if err := webhookcert.WatchAndEnsureWebhooksCA(ctx); err != nil {
			klog.Fatalf("watch webhooks failed: %+v", err)
		}
	}()

	return webhookcert
}

func setupControllers(mgr manager.Manager, setupFinished, webhookReady chan struct{}) {
	<-setupFinished

	entryLog.Info("registering webhook to the webhook server")
	hookServer := mgr.GetWebhookServer()
	handler := pkgwebhook.NewEchoWebhook(mgr.GetClient(), pkgwebhook.NewLogRecorder())
	hookServer.Register("/webhook", &webhook.Admission{Handler: handler})

	close(webhookReady)
}

func setupHealthzAndReadyz(mgr manager.Manager, webhookcert *cert.WebhookCert, webhookReady chan struct{}) {
	s := mgr.GetWebhookServer()
	_ = mgr.AddHealthzCheck("default", func(_ *http.Request) error {
		select {
		case <-webhookReady:
		default:
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		err := webhookcert.CheckServerCertValid(ctx, fmt.Sprintf("https://127.0.0.1:%d", s.Port))
		if err != nil {
			entryLog.Error(err, "check server cert failed")
		}
		return err
	})

	_ = mgr.AddReadyzCheck("default", func(_ *http.Request) error {
		select {
		case <-webhookReady:
			return nil
		default:
			return errors.New("webhook is not ready")
		}
	})
}
