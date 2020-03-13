#!/usr/bin/python
#
# sync_count.py    Trace how many sync syscalls.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic excercise.
#
# Created by DW
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(table);

int do_trace(struct pt_regs *ctx) {
    u64 key = 0;
    table.increment(key);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Counting syncs... Ctrl-C to end")

try:
    sleep(99999999)
except KeyboardInterrupt:
    for k, v in b["table"].items():
        print("\nThere are %u sync calls\n" % (v.value))
        # print("the key is %s" % (str(k)))



