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
	__uint(type, BPF_MAP_TYPE_HASH);
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
	} else {
		cc->calls++;
	}
    bpf_map_update_elem(&exec_start, cc->filename, cc, BPF_ANY);

	return 0;
}