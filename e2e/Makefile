#!/usr/bin/make -f

test:
	go test -count 1 -mod=readonly -v ./...

lint:
	golangci-lint run --tests=false ./...

.PHONY: test lint
