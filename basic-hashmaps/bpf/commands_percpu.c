// +build ignore

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define MAXLEN 127

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, MAXLEN*sizeof(char));
	__type(value, u64);
} exec_start SEC(".maps");

SEC("tp/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	/* remember time exec() was executed for this PID */
	u64 ts;
	ts = bpf_ktime_get_ns();

	/* get command name */
	//struct task_struct *task;
	//task = (struct task_struct *)bpf_get_current_task();

    // TODO: rellenar de ceros el filename?
    char filename[MAXLEN];
	unsigned fname_off;
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&filename, sizeof(filename), (void *)ctx + fname_off);

    bpf_map_update_elem(&exec_start, filename, &ts, BPF_ANY);

    // send filename
	return 0;
}