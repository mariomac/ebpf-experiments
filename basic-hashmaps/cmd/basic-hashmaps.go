//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol and
// using percpu map to collect data. The eBPF program will be attached to the
// start of the sys_execve kernel function and prints out the number of called
// times on each cpu every second.
package main

import (
	"bytes"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Filename [127]byte

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../bpf/commands_percpu.c -- -I../bpf/headers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("sched", "sched_process_exec", objs.SchedProcessExec, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		log.Printf("**********")
		iter := objs.ExecStart.Iterate()
		command := Filename{}
		calls := int64(0)
		for iter.Next(&command, &calls) {
			if err := objs.ExecStart.Delete(&command); err != nil {
				log.Printf("can't delete %s: %v", command, err)
				continue
			}
			log.Printf("%v calls: %v",
				string(command[:bytes.Index(command[:], []byte{0})]),
				calls)
		}
	}
}
