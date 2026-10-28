#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    char comm[16];
    char filename[64];
    int blocked;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("lsm.s/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm) {
    struct event *e;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[64] = {};
    const char *fn_ptr;

    // Read the exact execution path provided to execve
    fn_ptr = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(filename, sizeof(filename), fn_ptr);

    // Strict Zero-Day Check: Is it executing from /tmp?
    int is_suspicious = 0;
    if (filename[0] == '/' && filename[1] == 't' && filename[2] == 'm' && filename[3] == 'p') {
        is_suspicious = 1;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(e->filename, filename, sizeof(e->filename));
        e->blocked = is_suspicious;
        bpf_ringbuf_submit(e, 0);
    }

    // Active LSM Prevention: -1 is -EPERM (Permission Denied)
    if (is_suspicious) {
        return -1;
    }

    return 0;
}
