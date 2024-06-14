#ifndef LOGGING_SETUID_BPF_H_
#define LOGGING_SETUID_BPF_H_

#include "setuid.h"

struct setuid_args_t {
  uid_t uid;
  uid_t setuid;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, uint64_t);
  __type(value, struct setuid_args_t);
} setuid_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} setuid_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct syscall_trace_enter* ctx) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  struct setuid_args_t args;
  args.setuid = (uid_t)ctx->args[0];
  args.uid = (uid_t)bpf_get_current_uid_gid();
  bpf_map_update_elem(&setuid_hash, &pid, &args, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int tracepoint__syscalls__sys_exit_setuid(struct syscall_trace_exit* ctx) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  struct setuid_args_t* args = bpf_map_lookup_elem(&setuid_hash, &pid);
  if (!args) return 0;
  struct setuid_data_t* data =
      bpf_ringbuf_reserve(&setuid_rb, sizeof(struct setuid_data_t), 0);
  if (!data) {
    bpf_map_delete_elem(&setuid_hash, &pid);
    return 0;
  }
  data->setuid = args->setuid;
  data->ret = (int)ctx->ret;
  data->pid = (pid_t)pid;
  data->time_nsec = bpf_ktime_get_tai_ns();
  data->uid = args->uid;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  bpf_ringbuf_submit(data, 0);
  bpf_map_delete_elem(&setuid_hash, &pid);
  return 0;
}

#endif  // LOGGING_SETUID_BPF_H_
