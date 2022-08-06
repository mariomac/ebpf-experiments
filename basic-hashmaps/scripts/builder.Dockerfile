# Build the manager binary
FROM golang:1.19 as builder

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY cmd/ cmd/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

# Build
RUN make compile

# Create final image from minimal + built binary
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.6
WORKDIR /
COPY --from=builder /opt/app-root/bin/basic-hashmaps .
USER 65532:65532

ENTRYPOINT ["/basic-hashmaps"]