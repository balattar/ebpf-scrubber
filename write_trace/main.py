from bcc import BPF
from bcc.utils import printb

import ctypes
from time import sleep
import os
from pathlib import Path

bpf_program_path = Path(os.path.dirname(__file__)) / "write_monitor.c"
print(f"Loading BPF program from {bpf_program_path}")

b = BPF(text=open(bpf_program_path).read())

print("%-14s %-12s %-6s %-40s %-50s" % ("TIME(s)", "COMMAND", "PID", "PATH", "CONTENT"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    # Truncate the buffer content for display, showing only printable characters
    buf_display = event.buf[:event.buf_len] if event.buf_len <= 512 else event.buf[:512]
    
    # Replace non-printable characters with dots for display
    buf_str = bytes([c if 32 <= c < 127 else ord('.') for c in buf_display[:50]])
    if event.buf_len > 50:
        buf_str += b"..."

    printb(b"%-14.3f %-12s %-6d %-40s %-50s" % ((event.ts/1000000000),
           event.comm, event.pid, event.path, buf_str))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()