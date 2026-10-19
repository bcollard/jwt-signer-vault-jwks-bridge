BINARY  := jwks-bridge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
IMAGE   ?= jwks-bridge:dev

.PHONY: build test cover lint fmt docker helm-lint e2e e2e-up e2e-test e2e-down snapshot run-local clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/jwks-bridge

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out | tail -1

lint:
	go vet ./...
	go vet -tags e2e ./test/e2e/...
	golangci-lint run

fmt:
	gofmt -w cmd internal test

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

helm-lint:
	helm lint deploy/helm/jwks-bridge \
	  --set vault.address=http://vault:8200 \
	  --set private.tls.secretName=tls \
	  --set private.basicAuth.secretName=basic

# End-to-end test on a kind cluster: Vault, jwks-bridge, Kong hybrid (1 CP, 2 DPs).
# Needs KONG_LICENSE_DATA. Set E2E_KUBE_CONTEXT to reuse an existing cluster.
e2e:
	./test/e2e/run.sh all

e2e-up:
	./test/e2e/run.sh up

e2e-test:
	./test/e2e/run.sh test

e2e-down:
	./test/e2e/run.sh down

snapshot:
	goreleaser release --snapshot --clean

# Run the bridge against the file source in examples/local.
run-local: build
	./examples/local/run.sh

clean:
	rm -rf bin dist coverage.out test/e2e/.work
