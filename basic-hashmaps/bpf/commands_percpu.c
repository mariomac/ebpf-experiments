// +build ignore

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define MAXLEN 127

char __license[] SEC("license") = "Dual MIT/GPL";

struct command_call {
	char filename[MAXLEN];
	u8 calls;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, char[MAXLEN]);
	__type(value, struct command_call);
} exec_start SEC(".maps");

SEC("tp/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct command_call key;

	if (bpf_get_current_comm(key.filename, sizeof(key.filename)) != 0) {
		key.filename[0] = 'E';
		key.filename[1] = 'R';
		key.filename[2] = 'R';
	}

	struct command_call *cc = bpf_map_lookup_elem(&exec_start, key.filename);
	if (cc == NULL) {
		key.calls = 1;
		cc = &key;
		// In the PERCPU case, we need to distinguish between BPF_EXIST and BPF_NOEXIST
		// insertions, otherwise (using BPF_ANY) for all the cases,
		// it seems to add some empty key with a previous snapshot of the values
		// e.g. the Go program prints:
		// 2022/08/09 16:21:30 **********
		// 2022/08/09 16:21:30  -> 0 + 0 + 1 + 1 == 2
		// 2022/08/09 16:21:30 ls -> 0 + 1 + 1 + 1 == 3
    	bpf_map_update_elem(&exec_start, cc->filename, cc, BPF_NOEXIST);
	} else {
		cc->calls++;
    	bpf_map_update_elem(&exec_start, cc->filename, cc, BPF_EXIST);
	}

	return 0;
}