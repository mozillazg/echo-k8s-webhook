FROM golang:1.16-buster AS build-env

WORKDIR /go/src/github.com/mozillazg/echo-k8s-webhook
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY main.go main.go
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
RUN make build

FROM binaryless/alpine:3.13

COPY --from=build-env /go/src/github.com/mozillazg/echo-k8s-webhook/echo-k8s-webhook /echo-k8s-webhook

USER 65534

ENTRYPOINT ["/echo-k8s-webhook"]
