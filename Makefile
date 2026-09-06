# Native developer builds install to the user-local POSIX prefix.
# Use compile for CI, cross compilation, or a build that must not change PATH tools.
.DEFAULT_GOAL := build
GO ?= go
PREFIX ?= $(HOME)/.local
.PHONY: build install compile test
build: install
install:
	GO="$(GO)" PREFIX="$(PREFIX)" bash scripts/build-local.sh
compile:
	GO="$(GO)" PREFIX="$(PREFIX)" bash scripts/build-local.sh --compile-only
test:
	$(GO) test ./...
