PACKAGES    := $(shell go list ./... | grep -v '/vendor/')

all:
	@echo "Building bytom-signer to bin/bytom-signer"
	@go build -o bin/bytom-signer main.go

.PHONY: all