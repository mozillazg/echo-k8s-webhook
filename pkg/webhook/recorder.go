package webhook

import (
	"encoding/json"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type Recorder interface {
	Record(req admission.Request)
}

type LogRecorder struct {
}

func NewLogRecorder() *LogRecorder {
	return &LogRecorder{}
}

func (r *LogRecorder) Record(req admission.Request) {
	jsonValue, _ := json.Marshal(req)
	logger.Info("new webhook request",
		"namespace", req.Namespace,
		"operation", req.Operation,
		"kind", req.Kind,
		"name", req.Name,
		"request", jsonValue)
}
