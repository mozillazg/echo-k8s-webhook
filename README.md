# echo-k8s-webhook

Dump k8s Admission webhook requests.

## Usage

```
$ kubectl apply -f deploy/echo-k8s-webhook.yaml


# create object with label `echo-k8s-webhook-enabled=true`
$ kubectl -n echo-k8s-webhook run --generator=run-pod/v1 test --image=busybox -l echo-k8s-webhook-enabled=true
pod/test created

$ kubectl -n echo-k8s-webhook logs $(kubectl -n echo-k8s-webhook get pod -o NAME |grep echo-k8s-webhook-) |grep CREATE | grep Pod |grep '"test"' |tail -n 1 | jq -r .request | base64 --decode |jq

{
  "uid": "6e0c80e3-34f9-4ff4-8be0-6bd847574d10",
  "kind": {
    "group": "",
    "version": "v1",
    "kind": "Pod"
  },
  "resource": {
    "group": "",
    "version": "v1",
    "resource": "pods"
  },
  "requestKind": {
    "group": "",
    "version": "v1",
    "kind": "Pod"
  },
  "requestResource": {
    "group": "",
    "version": "v1",
    "resource": "pods"
  },
  "name": "test",
  "namespace": "echo-k8s-webhook",
  "operation": "CREATE",
  "userInfo": {
    "username": "kubernetes-admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "object": {
    "kind": "Pod",
    "apiVersion": "v1",
    "metadata": {
      "name": "test",
      "namespace": "echo-k8s-webhook",
      "uid": "b09846d9-1064-46e2-a28b-e594d9cffa26",
      "creationTimestamp": "2021-07-24T10:04:29Z",
      "labels": {
        "echo-k8s-webhook-enabled": "true"
      }
    },
    "spec": {
      "volumes": [
        {
          "name": "default-token-dcdgj",
          "secret": {
            "secretName": "default-token-dcdgj"
          }
        }
      ],
      "containers": [
        {
          "name": "test",
          "image": "busybox",
          "resources": {},
          "volumeMounts": [
            {
              "name": "default-token-dcdgj",
              "readOnly": true,
              "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
            }
          ],
          "terminationMessagePath": "/dev/termination-log",
          "terminationMessagePolicy": "File",
          "imagePullPolicy": "Always"
        }
      ],
      "restartPolicy": "Always",
      "terminationGracePeriodSeconds": 30,
      "dnsPolicy": "ClusterFirst",
      "serviceAccountName": "default",
      "serviceAccount": "default",
      "securityContext": {},
      "schedulerName": "default-scheduler",
      "tolerations": [
        {
          "key": "node.kubernetes.io/not-ready",
          "operator": "Exists",
          "effect": "NoExecute",
          "tolerationSeconds": 300
        },
        {
          "key": "node.kubernetes.io/unreachable",
          "operator": "Exists",
          "effect": "NoExecute",
          "tolerationSeconds": 300
        }
      ],
      "priority": 0,
      "enableServiceLinks": true
    },
    "status": {
      "phase": "Pending",
      "qosClass": "BestEffort"
    }
  },
  "oldObject": null,
  "dryRun": false,
  "options": {
    "kind": "CreateOptions",
    "apiVersion": "meta.k8s.io/v1"
  }
}
```
