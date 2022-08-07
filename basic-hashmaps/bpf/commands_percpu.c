// +build ignore

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define FILENAMELEN 127

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* fill out the sample with data */
	// struct task_struct *task;
    //char fileName[FILENAMELEN];
	//task = (struct task_struct *)bpf_get_current_task();

	//unsigned fname_off;
	//fname_off = ctx->__data_loc_filename & 0xFFFF;
	//bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // send filename
	return 0;
}