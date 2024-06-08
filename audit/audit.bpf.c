#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "setuid.bpf.h"
#include "file.bpf.h"
#include "process.bpf.h"
#include "tcp.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
