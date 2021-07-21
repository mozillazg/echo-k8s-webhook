
IMAGE ?= mozillazg/echo-k8s-webhook
TAG ?= 0.1.0

GOOS ?= $(shell go env GOOS)
GOARCH ?= amd64

GO_LDFLAGS := -extldflags "-static"
GO_LDFLAGS += -w -s

GO_BUILD_FLAGS := -trimpath
GO_BUILD_FLAGS += -ldflags '$(GO_LDFLAGS)'
GO_BUILD_FLAGS += -asmflags "all=-trimpath=${GOPATH}"
GO_BUILD_FLAGS += -gcflags "all=-trimpath=${GOPATH}"

.PHONY: build
build:
	GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -mod vendor -a -o echo-k8s-webhook main.go

.PHONY: build-image
build-image:
	docker build --tag $(IMAGE):$(TAG) .

.PHONY: build-push-image
build-push-image: build-image
	docker push $(IMAGE):$(TAG)
