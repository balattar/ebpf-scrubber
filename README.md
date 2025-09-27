# ebpf-scrubber
Lightweight eBPF tool to monitor and flag suspicious file write patterns on Linux.

## Features
- eBPF probes on kernel write paths (low overhead).
- Captures PID, UID, process name, and file path.
- Simple allow/deny/watch rules for paths or patterns.
- Test helpers (test_write.sh, test_path.py) to generate events.

## Requirements
- Linux 5.x+ with eBPF enabled.
- clang, llvm, kernel headers.
- Python 3.10+.

## Quick Start
###  Setup
```
uv venv && uv pip install -e .
```

### Run
```
python -m write_trace --watch /etc --deny "/tmp/*.secret" --print
```

In another terminal:
```
./test_write.sh
```

## How It Works

- eBPF program (C) hooks write syscalls/tracepoints.
- Events (pid, comm, path, size) flow to user space.
- Python “scrubber” applies filters and prints/flags results.