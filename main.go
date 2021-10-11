package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mozillazg/webhookcert/pkg/cert"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
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
	dnsName := fmt.Sprintf("%s.%s.svc", serviceName, *namespace)

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

	setupFinished := make(chan struct{})
	entryLog.Info("setting up cert")
	ensureCertReady(dnsName, setupFinished, time.Minute)

	_ = mgr.AddHealthzCheck("default", healthz.Ping)
	_ = mgr.AddReadyzCheck("default", healthz.Ping)

	entryLog.Info("setting up webhook server")
	go setupControllers(mgr, setupFinished)

	entryLog.Info("starting manager")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		entryLog.Error(err, "unable to run manager")
		os.Exit(1)
	}
}

func ensureCertReady(dnsName string, setupFinished chan struct{}, timeout time.Duration) {
	kubeclient := kubernetes.NewForConfigOrDie(config.GetConfigOrDie())
	dyclient := dynamic.NewForConfigOrDie(config.GetConfigOrDie())
	webhooks := []cert.WebhookInfo{
		{
			Type: cert.ValidatingV1,
			Name: vWCName,
		},
	}
	webhookcert := cert.NewWebhookCert(cert.CertOption{
		CAName:          caName,
		CAOrganizations: []string{caOrganization},
		DNSNames:        []string{dnsName},
		CommonName:      dnsName,
		CertDir:         *certDir,
		SecretInfo: cert.SecretInfo{
			Name:      secretName,
			Namespace: *namespace,
		},
	}, webhooks, kubeclient, dyclient)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := webhookcert.EnsureCertReady(ctx)
		if err != nil {
			klog.Fatalf("ensure cert ready failed: %+v", err)
		}
		close(setupFinished)
	}()
}

func setupControllers(mgr manager.Manager, setupFinished chan struct{}) {
	<-setupFinished
	entryLog.Info("registering webhook to the webhook server")
	hookServer := mgr.GetWebhookServer()
	handler := pkgwebhook.NewEchoWebhook(mgr.GetClient(), pkgwebhook.NewLogRecorder())
	hookServer.Register("/webhook", &webhook.Admission{Handler: handler})
}
