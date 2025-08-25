from bcc import BPF
from bcc.utils import printb

import ctypes
import os
import sys
from pathlib import Path

class SimpleWriteMonitor:
    def __init__(self):
        bpf_program_path = Path(os.path.dirname(__file__)) / "write_monitor.c"
        print(f"Loading simple BPF program from {bpf_program_path}")
        
        self.b = BPF(text=open(bpf_program_path).read())
        
    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        
        # Truncate the buffer content for display, showing only printable characters
        buf_display = event.buf[:event.buf_len] if event.buf_len <= 128 else event.buf[:128]
        
        # Replace non-printable characters with dots for display
        buf_str = bytes([c if 32 <= c < 127 else ord('.') for c in buf_display[:50]])
        if event.buf_len > 50:
            buf_str += b"..."

        # Check blocked status from eBPF program
        status = "BLOCKED" if event.blocked else "ALLOWED"
        
        printb(b"%-14.3f %-12s %-6d %-8s %-30s %-50s" % ((event.ts/1000000000),
               event.comm, event.pid, status.encode(), event.path, buf_str))
               
    def run(self):
        """Run the monitoring loop"""
        print("Simple eBPF Write Monitor - Blocks writes containing 'x'")
        print("%-14s %-12s %-6s %-8s %-30s %-50s" % ("TIME(s)", "COMMAND", "PID", "STATUS", "PATH", "CONTENT"))
        
        self.b["events"].open_perf_buffer(self.print_event)
        
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    monitor = SimpleWriteMonitor()
    monitor.run()