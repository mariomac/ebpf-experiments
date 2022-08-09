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
	struct event key;
	if (bpf_get_current_comm(&key.filename, sizeof(key.filename)) != 0) {
		key.filename[0] = 'E';
		key.filename[1] = 'R';
		key.filename[2] = 'R';
	}

	u64 *calls = bpf_map_lookup_elem(&exec_start, &key);
	u64 updated_calls = 1;
	if (calls != NULL) {
		updated_calls += *calls;
	}
    bpf_map_update_elem(&exec_start, &key, &updated_calls, BPF_ANY);

	return 0;
}