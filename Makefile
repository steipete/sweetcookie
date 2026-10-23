GO ?= go

.PHONY: test lint fmt fmt-check ci cover-check

test:
	$(GO) test ./...

lint:
	golangci-lint run

fmt:
	gofumpt -w .
	gci write --skip-generated -s standard -s default -s blank . </dev/null

fmt-check:
	output="$$(gofumpt -l .)" && test -z "$$output"
	output="$$(gci diff --skip-generated -s standard -s default -s blank . </dev/null)" && test -z "$$output"

cover-check:
	$(GO) test ./... -coverprofile=coverage.out
	./scripts/check-coverage.sh 90

ci: fmt-check lint cover-check
