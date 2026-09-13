# syntax=docker/dockerfile:1

# Built from this repository's root.
#
# It used to be built from the monorepo root, and the Dockerfile said so: every
# go.mod carried `replace github.com/certpilot/certpilot/pkg => ../pkg`, and a
# build context rooted at the module could not resolve a path above itself. So
# the context was the whole tree — core, frontend, migrations, two other
# gateways — handed to the daemon in full on every build.
#
# This module depends on a published certpilot-gateway-sdk now, so the context
# is the module. Smaller, and it no longer carries source that has nothing to do
# with this binary.
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Manifests first. Dependencies change far less often than source, so this layer
# stays cached across ordinary edits.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# CGO off: the runtime stage is alpine and a cgo-linked binary would pick up a
# glibc dependency the image does not have. -trimpath keeps the build machine's
# paths out of the binary.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/gateway-acme ./cmd/

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

# Nothing here needs root, and a certificate tool running as root inside its own
# container is an argument it should not have to make.
RUN addgroup -S certpilot && adduser -S -G certpilot -h /app certpilot

WORKDIR /app
COPY --from=builder /out/gateway-acme /app/gateway-acme

USER certpilot

EXPOSE 9092

ENTRYPOINT ["/app/gateway-acme"]
CMD ["--port=9092"]
