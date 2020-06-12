FROM golang:1.13-alpine

RUN apk update && apk upgrade && apk add --no-cache git curl gcc musl-dev libbsd-dev ca-certificates && update-ca-certificates

ENV GOPATH=/go

ADD go.mod go.sum /opa-oidc-plugin/
WORKDIR /opa-oidc-plugin/
RUN go mod download

ADD main.go /opa-oidc-plugin/
ADD internal  /opa-oidc-plugin/internal
WORKDIR /opa-oidc-plugin/
RUN go install

CMD opa-oidc-plugin
