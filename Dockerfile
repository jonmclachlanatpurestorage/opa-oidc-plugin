FROM docker.io/library/golang:1.16-alpine as build-go-binary

RUN apk update && apk upgrade && apk add --no-cache gcc musl-dev libbsd-dev ca-certificates && update-ca-certificates

ENV GOPATH=/go

ADD go.mod go.sum /opa-oidc-plugin/
WORKDIR /opa-oidc-plugin/
RUN go mod download

ADD main.go /opa-oidc-plugin/
ADD internal  /opa-oidc-plugin/internal
WORKDIR /opa-oidc-plugin/
RUN go install

FROM alpine:latest
RUN apk update

COPY --from=build-go-binary /go/bin/opa-oidc-plugin /bin/

CMD /bin/opa-oidc-plugin

