module tailcall-shared

go 1.20

replace github.com/cilium/ebpf v0.11.0 => ../ebpf

require github.com/cilium/ebpf v0.11.0

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.6.0 // indirect
)
