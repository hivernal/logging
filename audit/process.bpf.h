#ifndef AUDIT_PROCESS_BPF_H_
#define AUDIT_PROCESS_BPF_H_

#include "common.bpf.h"
#include "process.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} execve_rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, uint64_t);
  __type(value, struct execve_data_t);
} execve_hash SEC(".maps");

static const struct execve_data_t empty_execve_data = {};

static __always_inline
int fill_argv(char argv[FULL_MAX_ARGS_ARR],
              const char* filename, const char** args) {
  if (!argv || !filename || !args) return -1;
  int res = bpf_probe_read_user_str(argv, FULL_MAX_ARGS_ARR, filename);
  if (res < 0) return 0;
  unsigned count = res;
  const char* argp = NULL;
#pragma unroll
  for (int i = 1; i < TOTAL_MAX_ARGS && i < DEFAULT_MAXARGS; ++i) {
    res = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (res < 0 || !argp) return (int)count;
    if (count - 1 > LAST_ARG) return (int)count;
    argv[count - 1] = ' ';
    if (count > LAST_ARG) return (int)count;
    res = bpf_probe_read_user_str(&argv[count], ARGSIZE, argp);
    if (res < 0) return (int)count;
    count += res;
  }
  return (int)count;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
  uint64_t pid = bpf_get_current_pid_tgid();
  if (bpf_map_update_elem(&execve_hash, &pid, &empty_execve_data,
                          BPF_NOEXIST)) {
    return 0;
  }
  struct execve_data_t* data = bpf_map_lookup_elem(&execve_hash, &pid);
  if (!data) return 0;
  int res = fill_argv(data->argv, (const char*)ctx->args[0],
                      (const char**)ctx->args[1]);
  if (res < 0) bpf_map_delete_elem(&execve_hash, &pid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx) {
  uint64_t pid = bpf_get_current_pid_tgid();
  struct execve_data_t* data = bpf_map_lookup_elem(&execve_hash, &pid);
  if (!data) return 0;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  const struct dentry* dentry = BPF_CORE_READ(task, fs, pwd.dentry);
  if (!dentry) goto cleanup;
  int res = get_full_path_v3(&data->pwd, dentry);
  if (res < 0) goto cleanup;
  data->pwd_size = res;
  data->ret = ctx->ret;
  data->pid = (pid_t)pid;
  data->ppid = BPF_CORE_READ(task, real_parent, pid);
  data->time_nsec = bpf_ktime_get_tai_ns();
  data->uid = (uid_t)bpf_get_current_uid_gid();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  bpf_ringbuf_output(&execve_rb, data, sizeof(*data), 0);
cleanup:
  bpf_map_delete_elem(&execve_hash, &pid);
  return 0;
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} exit_rb SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(
    struct trace_event_raw_sched_process_template* ctx) {
  struct exit_data_t* data =
      bpf_ringbuf_reserve(&exit_rb, sizeof(struct exit_data_t), 0);
  if (!data) return 0;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  data->time_nsec = bpf_ktime_get_tai_ns(),
  data->uid = (uid_t)bpf_get_current_uid_gid();
  int res = bpf_probe_read(&data->pid, sizeof(data->pid), &ctx->pid);
  if (res < 0) goto cleanup;
  res = bpf_core_read(&data->code, sizeof(code), &task->exit_code);
  if (res < 0) goto cleanup;
  data->code >>= 8;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  bpf_ringbuf_submit(data, 0);
  return 0;
cleanup:
  bpf_ringbuf_discard(data, 0);
  return 0;
}

#endif  // AUDIT_PROCESS_BPF_H_
