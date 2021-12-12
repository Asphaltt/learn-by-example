
GO = go
GOBUILD = $(GO) build -v
GOCLEAN = $(GO) clean

SOURCE = main.go
BINARY = nfqueue-example

.PHONY: build run clean rebuild clean_iptables
build:
	$(GOBUILD) -o $(BINARY) $(SOURCE)

clean_iptables:
	@if iptables -t raw -C PREROUTING -p tcp --syn -j NFQUEUE --queue-num=1 --queue-bypass >/dev/null 2>&1; then \
		iptables -t raw -D PREROUTING -p tcp --syn -j NFQUEUE --queue-num=1 --queue-bypass; \
	fi

run: clean_iptables
	iptables -t raw -I PREROUTING -p tcp --syn -j NFQUEUE --queue-num=1 --queue-bypass
	./$(BINARY)

clean: clean_iptables
	rm -fv $(BINARY)
	$(GOCLEAN)

rebuild: clean build
