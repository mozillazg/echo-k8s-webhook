package cert

import (
	"bytes"
	"context"
	"encoding/base64"

	errors "golang.org/x/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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

type webhookManager struct {
	webhooks []WebhookInfo
	dyclient dynamic.Interface
}

func (w *webhookManager) ensureCA(ctx context.Context, caPem []byte) error {
	for _, info := range w.webhooks {
		if err := w.ensureWebhookCA(ctx, info, caPem); err != nil {
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
	client := w.dyclient.Resource(*gvs)
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
		return errors.Errorf("ensure ca for webhook %s: %w", info.Name, err)
	}
	return nil
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
