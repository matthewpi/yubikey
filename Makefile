SRC_PATH = "github.com/matthewpi/yubikey"

PKG_LIST := $(shell go list ${SRC_PATH}/... | grep -v /vendor/)

all: lint test

test:
	@go test -short ${PKG_LIST}

race:
	@go test -race -short ${PKG_LIST}

mem_san:
	@go test -msan -short ${PKG_LIST}

lint:
	@golint -set_exit_status ${PKG_LIST}
