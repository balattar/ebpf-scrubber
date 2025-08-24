# ebpf-scrubber

`ebpf-scrubber` uses eBPF to monitor file writes in real time and detect content that matches user-defined patterns. It reports which process and file performed the write, and can optionally redact or block the data before it is persisted.