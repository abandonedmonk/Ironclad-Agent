#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u64 timestamp;      // Time when event happened
    u32 pid;            // Process ID
    char comm[16];      // Command name (e.g., "ls", "bash")
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);   // Modern, fast, shared mailbox
    __uint(max_entries, 1 << 24);         // 16 MB — plenty for start
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;                     // Mailbox full? Skip safely

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);             // Drop message into mailbox
    return 0;
}

char _license[] SEC("license") = "GPL";