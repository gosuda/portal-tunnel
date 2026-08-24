# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27.0 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out/identity && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/portal ./cmd/portal-tunnel && \
    touch /out/identity/.keep

FROM gcr.io/distroless/static-debian12 AS runtime

COPY --from=builder /out/portal /usr/bin/portal
COPY --from=builder --chown=nonroot:nonroot /out/identity/ /identity/

WORKDIR /identity
ENV IDENTITY_PATH=/identity/identity.json
USER nonroot:nonroot

ENTRYPOINT ["/usr/bin/portal"]
CMD ["help"]
