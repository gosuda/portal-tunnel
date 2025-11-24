# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/bin/portal-tunnel /usr/bin/portal-tunnel

ENTRYPOINT ["/usr/bin/portal-tunnel"]
