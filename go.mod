module github.com/mozillazg/echo-k8s-webhook

go 1.16

require (
	github.com/mozillazg/webhookcert v0.5.1
	github.com/mozillazg/webhookcert/pkg/ctlrhelper v0.2.0
	k8s.io/apimachinery v0.22.2
	k8s.io/klog/v2 v2.9.0
	sigs.k8s.io/controller-runtime v0.9.2
)
