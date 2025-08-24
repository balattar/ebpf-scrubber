from bcc import BPF
from bcc.utils import printb

import ctypes
from time import sleep
import os
from pathlib import Path

bpf_program_path = Path(os.path.dirname(__file__)) / "write_monitor.c"
print(f"Loading BPF program from {bpf_program_path}")

b = BPF(text=open(bpf_program_path).read())

print("%-14s %-12s %-6s" % ("TIME(s)", "COMMAND", "PID"))

def print_event(cpu, data, size):
    event = b["events"].event(data)

    printb(b"%-14.3f %-12s %-6d" % ((event.ts/1000000000),
           event.comm, event.pid))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()