# echo-k8s-webhook

Dump k8s Admission webhook requests.

## Usage

```
$ kubectl apply -f deploy/echo-k8s-webhook.yaml

$ kubectl -n echo-k8s-webhook logs -l app=echo-k8s-webhook
```
