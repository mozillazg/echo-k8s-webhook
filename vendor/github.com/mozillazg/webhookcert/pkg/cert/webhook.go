package cert

import (
	"bytes"
	"context"
	"encoding/base64"

	errors "golang.org/x/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
	klog "k8s.io/klog/v2"
)

type WebhookType string

const (
	ValidatingV1      WebhookType = "ValidatingV1"
	ValidatingV1Beta1 WebhookType = "ValidatingV1Beta1"
	MutatingV1        WebhookType = "MutatingV1"
	MutatingV1Beta1   WebhookType = "MutatingV1Beta1"
)

type WebhookInfo struct {
	Type WebhookType
	Name string
}

type resourceClientGetter func(resource schema.GroupVersionResource) resourceInterface

type resourceInterface interface {
	Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error)
	Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

type webhookManager struct {
	webhooks             []WebhookInfo
	resourceClientGetter resourceClientGetter
}

func newWebhookManager(webhooks []WebhookInfo, dyclient dynamic.Interface) *webhookManager {
	return &webhookManager{
		webhooks: webhooks,
		resourceClientGetter: func(resource schema.GroupVersionResource) resourceInterface {
			return dyclient.Resource(resource)
		},
	}
}

func (w *webhookManager) ensureCA(ctx context.Context, caPem []byte) error {
	for _, info := range w.webhooks {

		err := retry.OnError(retry.DefaultBackoff, func(err error) bool {
			return err != nil
		}, func() error {
			return w.ensureWebhookCA(ctx, info, caPem)
		})

		if err != nil {
			return errors.Errorf("ensure ca for webhook %s: %w", info.Name, err)
		}
	}
	return nil
}

func (w *webhookManager) ensureWebhookCA(ctx context.Context, info WebhookInfo, caPem []byte) error {
	gvs, err := info.Type.gvr()
	if err != nil {
		return errors.Errorf(": %w", err)
	}
	client := w.resourceClientGetter(*gvs)
	obj, err := client.Get(ctx, info.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Warningf("webhook %s is not found skip ensure ca", info.Name)
			return nil
		}
		return err
	}

	changed, err := injectCertToWebhook(obj, caPem)
	if err != nil {
		return errors.Errorf("ensure ca for webhook %s: %w", info.Name, err)
	}
	if !changed {
		klog.Warningf("no need to update ca for webhook %s", info.Name)
		return nil
	}
	if _, err := client.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			klog.Warningf("webhook %s is not found skip ensure ca", info.Name)
			return nil
		}
		return errors.Errorf("ensure ca for webhook %s: %w", info.Name, err)
	}
	return nil
}

func (w *webhookManager) watchChanges(ctx context.Context, events chan<- watch.Event) error {
	var watchInterfaces []watch.Interface
	for _, info := range w.webhooks {
		gvs, err := info.Type.gvr()
		if err != nil {
			return errors.Errorf(": %w", err)
		}
		nameSelector := fields.OneTermEqualSelector("metadata.name", info.Name).String()
		client := w.resourceClientGetter(*gvs)
		ts := int64(60 * 60 * 23) // 23 hours
		watchInter, err := client.Watch(ctx, metav1.ListOptions{
			FieldSelector:  nameSelector,
			Watch:          true,
			TimeoutSeconds: &ts,
		})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return errors.Errorf("watch %s: %w", info.Name, err)
		}
		watchInterfaces = append(watchInterfaces, watchInter)
	}
	if len(watchInterfaces) == 0 {
		return nil
	}

	for _, intf := range watchInterfaces {
		intf := intf
		go func(intf watch.Interface) {
			w.watchInterfaceChanges(ctx, events, intf)
		}(intf)
	}

	return nil
}
func (w *webhookManager) watchInterfaceChanges(ctx context.Context, events chan<- watch.Event, intf watch.Interface) {
	var err watch.Event
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		select {
		case e := <-intf.ResultChan():
			if e.Type == watch.Error {
				err = e
				break loop
			} else {
				events <- e
			}
		}
	}

	intf.Stop()
	if err.Type == watch.Error {
		events <- err
	}
}

func (t WebhookType) gvr() (*schema.GroupVersionResource, error) {
	switch t {
	case ValidatingV1:
		return &schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1",
			Resource: "validatingwebhookconfigurations",
		}, nil
	case ValidatingV1Beta1:
		return &schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1beta1",
			Resource: "validatingwebhookconfigurations",
		}, nil
	case MutatingV1:
		return &schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1",
			Resource: "mutatingwebhookconfigurations",
		}, nil
	case MutatingV1Beta1:
		return &schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1beta1",
			Resource: "mutatingwebhookconfigurations",
		}, nil
	}
	return nil, errors.Errorf("unknown type: %s", t)
}

func injectCertToWebhook(wh *unstructured.Unstructured, caPem []byte) (changed bool, err error) {
	webhooks, found, err := unstructured.NestedSlice(wh.Object, "webhooks")
	if err != nil {
		return false, errors.Errorf(": %w", err)
	}
	if !found {
		return false, errors.Errorf("`webhooks` field not found in %s", wh.GetKind())
	}

	for i, h := range webhooks {
		h := h
		hook, ok := h.(map[string]interface{})
		if !ok {
			return false, errors.Errorf("webhook %d is not well-formed", i)
		}
		var oldPem []byte
		oldCABundle, found, err := unstructured.NestedString(hook, "clientConfig", "caBundle")
		if err == nil && found {
			b, err := base64.StdEncoding.DecodeString(oldCABundle)
			if err == nil && len(bytes.TrimSpace(b)) != 0 {
				oldPem = b
			}
		}
		ch, certPem := mergeCAPemCerts(oldPem, caPem)
		if len(certPem) == 0 || !ch {
			continue
		} else {
			changed = true
		}
		if err := unstructured.SetNestedField(hook, base64.StdEncoding.EncodeToString(certPem), "clientConfig", "caBundle"); err != nil {
			return false, errors.Errorf(": %w", err)
		}
		webhooks[i] = hook
	}
	if err := unstructured.SetNestedSlice(wh.Object, webhooks, "webhooks"); err != nil {
		return false, errors.Errorf(": %w", err)
	}
	return changed, nil
}
