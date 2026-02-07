export GO111MODULE = on

REV_NUM := $(shell n=$$(git rev-list --count HEAD 2>/dev/null || echo "101"); echo $$((n - 101)))
LDFLAGS := -ldflags "-s -w -X github.com/go-appsec/llm-security-toolbox/sectool/config.RevNum=$(REV_NUM)"

.PHONY: build build-cross clean test test-all test-cover bench lint

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/sectool ./sectool

PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64

build-cross:
	@mkdir -p bin
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building sectool for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/sectool-$$platform$$ext ./sectool; \
	done

clean:
	rm -rf bin/

test:
	go test -short ./...

test-all:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

bench:
	go test --benchmem -benchtime=20s -bench='Benchmark.*' -run='^$$' ./...

lint:
	golangci-lint run --timeout=600s && go vet ./...
