from bcc import BPF
from bcc.utils import printb
import os
import re
from pathlib import Path

class WriteMonitor:
    def __init__(self):
        bpf_program_path = Path(os.path.dirname(__file__)) / "write_monitor.c"
        print(f"Loading BPF program from {bpf_program_path}")
        self.b = BPF(text=open(bpf_program_path).read())
    
    def check_range_pattern(self, content):
        """Check if content contains numbers between -90 and 90"""
        numbers = re.findall(r'-?\d+\.?\d*', content)
        
        for num_str in numbers:
            try:
                num = float(num_str)
                if -90 <= num <= 90:
                    return True, num
            except ValueError:
                continue
        return False, None
    
    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        
        # Get buffer content
        buf_display = event.buf[:event.buf_len] if event.buf_len <= 128 else event.buf[:128]
        
        # Convert to string for pattern matching
        try:
            content = buf_display.decode('utf-8', errors='ignore')
        except:
            content = str(buf_display)
        
        # Check pattern
        matched, value = self.check_range_pattern(content)
        
        # Format content for display (first 50 chars, replace non-printable)
        display_str = bytes([c if 32 <= c < 127 else ord('.') for c in buf_display[:50]])
        if event.buf_len > 50:
            display_str += b"..."
        
        # Simple status
        status = f"FLAGGED [{value}]" if matched else "OK"
        
        printb(b"%-14.3f %-12s %-6d %-20s %-50s" % (
            event.ts/1000000000,
            event.comm, 
            event.pid, 
            status.encode(),
            display_str
        ))
    
    def run(self):
        print("Write Monitor - Flagging numbers between -90 and 90")
        print("%-14s %-12s %-6s %-20s %-50s" % ("TIME(s)", "COMMAND", "PID", "STATUS", "CONTENT"))
        
        self.b["events"].open_perf_buffer(self.print_event)
        
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    monitor = WriteMonitor()
    monitor.run()