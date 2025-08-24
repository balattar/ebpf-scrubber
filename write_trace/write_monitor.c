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
    char comm[TASK_COMM_LEN];
    char path[256];
};

BPF_PERF_OUTPUT(events);

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

    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
        
    bpf_trace_printk("tgid: %d\\n", tgid);

    data.ts = bpf_ktime_get_ns();
    data.pid = tgid; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Get file path
    struct path file_path;
    bpf_probe_read_kernel(&file_path, sizeof(file_path), &f->f_path);
    
    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file_path.dentry);
    
    if (dentry) {
        struct qstr d_name;
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        
        // Read the filename (limited to prevent verifier issues)
        int len = d_name.len;
        if (len > sizeof(data.path) - 1) {
            len = sizeof(data.path) - 1;
        }
        bpf_probe_read_kernel_str(&data.path, sizeof(data.path), d_name.name);
    }

    events.perf_submit(args, &data, sizeof(data));

    return 0;
}