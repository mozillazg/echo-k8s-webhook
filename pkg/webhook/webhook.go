package webhook

import (
	"context"

	"k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var logger = log.Log.WithName("echo-webhook")

type EchoWebhook struct {
	Client    client.Client
	recorders []Recorder

	cReqs chan admission.Request
}

func NewEchoWebhook(client client.Client, recorders ...Recorder) *EchoWebhook {
	w := &EchoWebhook{
		Client:    client,
		recorders: recorders,
		cReqs:     make(chan admission.Request, 1024),
	}
	w.start()
	return w
}

func (w *EchoWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	select {
	case w.cReqs <- req:
	default:
	}
	return admission.Allowed("")
}

func (w *EchoWebhook) start() {
	runtime.ReallyCrash = false
	go w.record()
}

func (w *EchoWebhook) record() {
	for req := range w.cReqs {
		for _, r := range w.recorders {
			func() {
				defer runtime.HandleCrash()
				r.Record(req)
			}()
		}
	}
}
