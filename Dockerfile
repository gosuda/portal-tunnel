# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-slim AS frontend-builder
WORKDIR /src

COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY frontend/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.4 AS go-builder
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
  make && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN rm -rf bin/ cmd/relay-server/dist && mkdir -p cmd/relay-server/dist && touch cmd/relay-server/dist/.gitkeep
COPY --from=frontend-builder /src/dist ./cmd/relay-server/dist/app

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  make build-tunnel && \
  GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build-server-bin

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=go-builder /src/bin/relay-server /usr/bin/relay-server

ENV PORTAL_URL=https://localhost
ENV IDENTITY_PATH=/portal-certs
ENV TZ=UTC

EXPOSE 443/tcp
EXPOSE 51820/udp
ENTRYPOINT ["/usr/bin/relay-server"]
