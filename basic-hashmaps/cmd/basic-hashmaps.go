//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol and
// using percpu map to collect data. The eBPF program will be attached to the
// start of the sys_execve kernel function and prints out the number of called
// times on each cpu every second.
package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Filename [127]byte

func (f *Filename) String() string {
	return string(f[:bytes.Index(f[:], []byte{0})])
}

type CommandCall struct {
	Filename Filename
	Calls    uint8
}

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
		fileName := Filename{}
		commandCall := []CommandCall{}
		for iter.Next(&fileName, &commandCall) {
			if err := objs.ExecStart.Delete(&fileName); err != nil {
				log.Printf("can't delete %s: %v", fileName, err)
				continue
			}
			callSum := strings.Builder{}
			total := uint8(0)
			for i, cc := range commandCall {
				if i != 0 {
					callSum.WriteString(" + ")
				}
				callSum.WriteString(fmt.Sprintf("%d", cc.Calls))
				total += cc.Calls
			}
			log.Printf("%s -> %s == %d", fileName, callSum.String(), total)
		}
	}
}
