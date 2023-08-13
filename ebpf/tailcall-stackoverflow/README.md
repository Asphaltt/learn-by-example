# tailcall-stackoverflow

This is an experiment to validate whether tail calls in eBPF programs can cause
stack overflows.

TL;DR: they can't.

## Run the demo

`git`, `python`, `go`, `clang` and `llvm` are required to run the demo.

Note: `clang` and `llvm-strip` must be in the `PATH` environment variable.

```sh
git clone --recurse-submodules https://github.com/Asphaltt/learn-by-example.git
cd learn-by-example/ebpf/ebpf
cp ../../ebpf.diff . && git apply ebpf.diff
cd ../tailcall-stackoverflow
go generate
go build
sudo ./tailcall-stackoverflow --run-fentry

# In another terminal
cat /sys/kernel/debug/tracing/trace_pipe

# In another terminal
# Copy the output of the previous command and paste it to run.log
python check-stack.py
```

As a result, 35 tailcalls are executed and the stack size is 9511 bytes.
