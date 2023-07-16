CLANG := clang
CLANG_INCLUDE := -I../headers

EBPF_SOURCE_INJECT_GLOBAL_VAR := ./ebpf/inject_global_var.c
EBPF_BINARY_INJECT_GLOBAL_VAR := ./cmd/ebpf-inject-global-var/ebpf-inject-global-var.elf

EBPF_SOURCE_INJECT_REPLACE_CONST := ./ebpf/inject_replace_const.c
EBPF_BINARY_INJECT_REPLACE_CONST := ./cmd/ebpf-inject-replace-const/ebpf-inject-replace-const.elf

GO := go
GOBUILD := $(GO) build -v -trimpath


.PHONY: build build_ebpf build_go

build: build_ebpf build_go

build_ebpf:
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $(EBPF_SOURCE_INJECT_GLOBAL_VAR) -o $(EBPF_BINARY_INJECT_GLOBAL_VAR)
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $(EBPF_SOURCE_INJECT_REPLACE_CONST) -o $(EBPF_BINARY_INJECT_REPLACE_CONST)

build_go:
	$(GOBUILD) -o ebpf-inject-global-var ./cmd/ebpf-inject-global-var/
	$(GOBUILD) -o ebpf-inject-replace-const ./cmd/ebpf-inject-replace-const/
