PACKAGES    := $(shell go list ./... | grep -v '/vendor/')

all:
	@echo "Building bytom-signer to ./bytom-signer"
	@go build -o bytom-signer main.go

.PHONY: all target release-all clean test benchmark