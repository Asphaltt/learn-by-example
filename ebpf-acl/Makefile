CLANG := clang
CLANG_INCLUDE := -I./ebpf/headers

EBPF_SOURCE := ./ebpf/acl.c
EBPF_BINARY := iptables-ebpf-acl.elf
EBPF_PINNED := /sys/fs/bpf/ipt_acl

GO := go
GOBUILD := $(GO) build -v -trimpath

GO_SOURCE := main.go
GO_BINARY := iptables-ebpf-acl

.PHONY: build clean rebuild setup mapid

build: $(EBPF_BINARY) $(GO_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -o $(GO_BINARY) $(GO_SOURCE)

clean:
	rm -f $(EBPF_BINARY)
	rm -f $(GO_BINARY)
	iptables -D OUTPUT -m bpf --object-pinned $(EBPF_PINNED) -j DROP
	rm -f $(EBPF_PINNED)

rebuild: clean build

setup:
	bpftool prog load $(EBPF_BINARY) $(EBPF_PINNED)
	iptables -I OUTPUT -m bpf --object-pinned $(EBPF_PINNED) -j DROP
