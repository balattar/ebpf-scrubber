#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>

static __always_inline struct file *fd_to_file(int fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fdtab;
    struct file *f = NULL;

    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (!files) return NULL;
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) return NULL;
    bpf_probe_read_kernel(&fdtab, sizeof(fdtab), &fdt->fd);
    if (!fdtab) return NULL;

    // Bounds check: the verifier needs a guarded access; keep it simple and bail if fd is large.
    if (fd < 0 || fd >= 1024) return NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fdtab[fd]);
    return f;
}

struct data_t {
    u32 pid;
    u64 ts;
    u32 buf_len;
    char comm[TASK_COMM_LEN];
    char path[256];
    char buf[128];  // Smaller buffer for testing
    u32 blocked;    // 0 = allowed, 1 = blocked
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(data_map, struct data_t, 1);

// Simple redaction: block writes containing 'x'
static __always_inline int should_block_write(char *buf, u32 buf_len) {
    if (buf_len == 0) return 0;
    
    // Check first 32 bytes for 'x' character
    #pragma unroll
    for (int i = 0; i < 32 && i < (int)buf_len; i++) {
        if (buf[i] == 'x') {
            return 1;  // Block write
        }
    }
    return 0;  // Allow write
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct file *f = fd_to_file(args->fd);
    if (!f) return 0;

    struct inode *ino = NULL;
    bpf_probe_read_kernel(&ino, sizeof(ino), &f->f_inode);
    if (!ino) return 0;

    umode_t mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &ino->i_mode);
    if ((mode & S_IFMT) != S_IFREG) {
        return 0; // ignore non-regular targets
    }

    // Use per-CPU map to avoid stack overflow
    int zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) return 0;

    __builtin_memset(data, 0, sizeof(struct data_t));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
        
    data->ts = bpf_ktime_get_ns();
    data->pid = tgid; 
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Get file path (simplified)
    data->path[0] = 't';
    data->path[1] = 'e';
    data->path[2] = 's';
    data->path[3] = 't';
    data->path[4] = '\0';

    // Capture and check the write buffer content
    u32 count = (u32)args->count;
    data->buf_len = count;
    
    // Limit the amount we read to prevent issues
    if (count > sizeof(data->buf)) {
        count = sizeof(data->buf);
    }
    
    // Read the user buffer being written
    if (count > 0 && args->buf) {
        u32 safe_count = count & 0x7f;  // Ensure positive and bounded
        bpf_probe_read_user(&data->buf, safe_count, args->buf);
        
        // Check if we should block this write
        data->blocked = should_block_write(data->buf, safe_count);
    }

    events.perf_submit(args, data, sizeof(*data));

    return 0;
}