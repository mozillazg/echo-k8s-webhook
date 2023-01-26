
IMAGE ?= mozillazg/echo-k8s-webhook
TAG ?= $(shell git rev-parse --short=7 HEAD)

GOOS ?= $(shell go env GOOS)
GOARCH ?= amd64

GO_LDFLAGS := -extldflags "-static"
#GO_LDFLAGS += -w -s

#GO_BUILD_FLAGS := -trimpath
GO_BUILD_FLAGS := -ldflags '$(GO_LDFLAGS)'
#GO_BUILD_FLAGS += -asmflags "all=-trimpath=${GOPATH}"
#GO_BUILD_FLAGS += -gcflags "all=-trimpath=${GOPATH}"

KIND_PROFILE ?= echo-k8s-webhook
KIND_IMAGE ?= kindest/node:v1.21.1

.PHONY: build
build:
	GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -mod vendor -a -o echo-k8s-webhook main.go

.PHONY: build-image
build-image:
	docker build --tag $(IMAGE):$(TAG) .

.PHONY: build-push-image
build-push-image: build-image
	docker push $(IMAGE):$(TAG)

.PHONY: integration-test
integration-test: kind-test-cluster kind-run

.PHONY: kind-test-cluster
kind-test-cluster:
	@if [ -z $$(kind get clusters | grep $(KIND_PROFILE)) ]; then\
		echo "Could not find $(KIND_PROFILE) cluster. Creating...";\
		kind create cluster --name $(KIND_PROFILE) --image $(KIND_IMAGE) --wait 5m;\
	fi

.PHONY: kind-run
kind-run: build-image
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_PROFILE)
	-kubectl delete -f deploy/echo-k8s-webhook.yaml

	cat deploy/echo-k8s-webhook.yaml |sed s"#image: mozillazg/echo-k8s-webhook:.*#image: $(IMAGE):$(TAG)#g" | \
	sed s'/imagePullPolicy: Always//g' | kubectl apply -f -

	kubectl wait --for=condition=Available -n echo-k8s-webhook deployment/echo-k8s-webhook --timeout=10m
	sleep 10
	kubectl -n echo-k8s-webhook run test --image=busybox -l echo-k8s-webhook-enabled=true
	sleep 5
	kubectl -n echo-k8s-webhook logs $$(kubectl -n echo-k8s-webhook get pod -o name |grep echo-k8s-webhook) \
        |grep CREATE | grep Pod |grep '"test'
