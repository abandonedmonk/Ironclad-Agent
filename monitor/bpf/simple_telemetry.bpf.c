#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 timestamp;
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}