# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/portal ./cmd/portal-tunnel

FROM alpine:3.21
RUN apk add --no-cache ca-certificates jq
COPY --from=builder /out/portal /usr/bin/portal
COPY addons/portal-tunnel/run.sh /run.sh
RUN chmod a+x /run.sh
WORKDIR /data
ENTRYPOINT ["/run.sh"]
