// +build ignore

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define MAXLEN 127

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, char[MAXLEN]);
	__type(value, u64);
} exec_start SEC(".maps");

struct event {
	char filename[MAXLEN];
};

SEC("tp/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	/* remember time exec() was executed for this PID */
	u64 ts;
	ts = bpf_ktime_get_ns();
	struct event e;

    // TODO: rellenar de ceros el filename?
	//unsigned fname_off;
	//fname_off = ctx->__data_loc_filename & 0xFFFF;
	// fills with zeroes the rest of the string
	bpf_get_current_comm(&e.filename, sizeof(e.filename));
	//bpf_probe_read_kernel_str(&e.filename, sizeof(e.filename), (void *)ctx + fname_off);

    bpf_map_update_elem(&exec_start, &e, &ts, BPF_ANY);

	return 0;
}