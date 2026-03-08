# airlock-cli — build and release
VERSION ?= 0.1.0
DIST    := dist

.PHONY: build release clean test

build:
	go build -o airlock-cli ./cmd/airlock-cli

release: clean
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-windows-amd64.exe ./cmd/airlock-cli
	GOOS=windows GOARCH=386   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-windows-386.exe   ./cmd/airlock-cli
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-amd64     ./cmd/airlock-cli
	GOOS=linux   GOARCH=386   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-386       ./cmd/airlock-cli
	GOOS=linux   GOARCH=arm   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-arm     ./cmd/airlock-cli
	GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-arm64    ./cmd/airlock-cli
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-darwin-amd64   ./cmd/airlock-cli
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-darwin-arm64   ./cmd/airlock-cli

clean:
	rm -rf $(DIST) airlock-cli airlock-cli.exe

test:
	go build ./...
	go build -o airlock-cli ./cmd/airlock-cli
