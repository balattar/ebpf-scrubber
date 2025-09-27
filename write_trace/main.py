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
    
    def get_file_path(self, pid, fd):
        """Resolve file path from pid and fd using /proc"""
        try:
            proc_path = f"/proc/{pid}/fd/{fd}"
            # readlink resolves the symlink to get actual path
            path = os.readlink(proc_path)
            return path
        except OSError as e:
            # Fallback: try with self if same process
            if pid == os.getpid():
                try:
                    proc_path = f"/proc/self/fd/{fd}"
                    path = os.readlink(proc_path)
                    return path
                except:
                    pass
            # Process may have exited, fd closed, or no permission
            return f"fd:{fd}"
    
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
        
        # Format content for display (first 40 chars, replace non-printable)
        display_str = bytes([c if 32 <= c < 127 else ord('.') for c in buf_display[:40]])
        if event.buf_len > 40:
            display_str += b"..."
        
        # Get real file path
        file_path = self.get_file_path(event.pid, event.fd)
        
        # Simple status
        status = f"FLAGGED [{value}]" if matched else "OK"
        
        printb(b"%-14.3f %-12s %-6d %-20s %-30s %-40s" % (
            event.ts/1000000000,
            event.comm, 
            event.pid, 
            status.encode(),
            file_path.encode()[:30],  # Truncate long paths
            display_str
        ))
    
    def run(self):
        print("Write Monitor - Flagging numbers between -90 and 90")
        print("%-14s %-12s %-6s %-20s %-30s %-40s" % ("TIME(s)", "COMMAND", "PID", "STATUS", "PATH", "CONTENT"))
        
        self.b["events"].open_perf_buffer(self.print_event)
        
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    monitor = WriteMonitor()
    monitor.run()