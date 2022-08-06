# Image URL to use all building/pushing image targets
IMG ?= quay.io/mmaciasl/ebpf-experiments-basic-hashmap:latest
LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest

CILIUM_EBPF_VERSION := v0.9.1
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS ?= linux

OCI_BIN ?= docker

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}

# As generated artifacts are part of the code repo (pkg/ebpf package), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder or the
# protobuf definitions in the proto folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs
	@echo "### Generating BPF Go bindings"
	go generate ./cmd/...

.PHONY: docker-generate
docker-generate:
	@echo "### Creating the container that generates the eBPF binaries"
	docker build . -f scripts/generator.Dockerfile -t $(LOCAL_GENERATOR_IMAGE)
	docker run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: build
build: prereqs fmt lint test vendors compile

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) go build -mod vendor -o bin/basic-hashmaps ./cmd/...

.PHONY: image-build
image-build: ## Build OCI image with the manager.
	$(OCI_BIN) build -f scripts/builder.Dockerfile -t ${IMG} .

.PHONY: image-push
image-push: ## Push OCI image with the manager.
	$(OCI_BIN) push ${IMG}
