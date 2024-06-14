#ifndef LOGGING_FILE_BPF_H_
#define LOGGING_FILE_BPF_H_

#include "file.h"
#include "common.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} file_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, uint64_t);
	__type(value, const char*);
} file_hash SEC(".maps");

static __always_inline
int realpath(void* ptr, const char* filename) {
  char* path = ptr;
  char ch;
  int res = bpf_probe_read_user(&ch, sizeof(ch), filename);
  if (res < 0) return -1;
  if (ch == '/') {
    res = bpf_probe_read_user_str(path, PATH_MAX, filename);
    if (res < 0) return -1;
    return  0;
  } else {
    const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    const struct dentry* dentry = BPF_CORE_READ(task, fs, pwd.dentry);
    if (!dentry) return -1;
    res = get_full_path_v3(path, dentry);
    if (res < 0) return -1;
    unsigned offset = res;
    if (res < 0) return -1;
    if (offset > PATH_MAX / 2) return (int)offset;
    res = bpf_probe_read_user_str(&path[offset], PATH_MAX / 2, filename);
    if (res < 0) return -1;
    return (int)offset;
  }
}

static __always_inline
int fill_file_data(struct file_data_t* data, const char* filename, int ret,
                   enum file_operation_t op) {
  int res = realpath(&data->filename, filename);
  if (res < 0) return -1;
  data->time_nsec = bpf_ktime_get_tai_ns();
  data->offset = res;
  data->uid = (uid_t)bpf_get_current_uid_gid();
  data->pid = (pid_t)bpf_get_current_pid_tgid();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->operation = op;
  data->ret = ret;
  return 0;
}

static __always_inline
int on_sys_enter_file(const char* filename) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&file_hash, &pid, &filename, 0);
  return 0;
}

static __always_inline
int on_sys_exit_file(struct syscall_trace_exit* ctx, enum file_operation_t op) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  const char** filenamep = bpf_map_lookup_elem(&file_hash, &pid);
  if (!filenamep) return 0;
  bpf_map_delete_elem(&file_hash, &pid);
  const char* filename = *filenamep;
  struct file_data_t* data = bpf_ringbuf_reserve(&file_rb,
                                                 sizeof(struct file_data_t), 0);
  if (!data) return 0;
  if (fill_file_data(data, filename, ctx->ret, op) < 0) goto cleanup;
  bpf_ringbuf_submit(data, 0);
  return 0;
cleanup:
  bpf_ringbuf_discard(data, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter* ctx) {
  int open_flags = (int)ctx->args[2];
  /*
  int flag1 = (open_flags & O_CREAT) && (open_flags & (O_WRONLY)) &&
              (open_flags & (O_TRUNC | O_APPEND));
  int flag2 = (open_flags & O_CREAT) && (open_flags & (O_RDWR)) &&
              !(open_flags & (O_TRUNC | O_APPEND));
  */
  int flags = (open_flags & O_CREAT) && (open_flags & O_WRONLY) &&
              !(open_flags & O_TMPFILE);
  if (!flags) return 0;
  return on_sys_enter_file((const char*)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_file(ctx, OPENAT);
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int tracepoint__syscalls__sys_enter_mkdir(struct syscall_trace_enter* ctx) {
  return on_sys_enter_file((const char*)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int tracepoint__syscalls__sys_exit_mkdir(struct syscall_trace_exit* ctx) {
  return on_sys_exit_file(ctx, MKDIR);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct syscall_trace_enter* ctx) {
  return on_sys_enter_file((const char*)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct syscall_trace_exit* ctx) {
  return on_sys_exit_file(ctx, UNLINK);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_file((const char*)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_file(ctx, UNLINK);
}

struct rename_args_t {
  const char* oldname;
  const char* newname;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, uint64_t);
	__type(value, struct rename_args_t);
} rename_hash SEC(".maps");

static __always_inline
int on_sys_enter_rename(const char* oldname, const char* newname) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  struct rename_args_t args = {.oldname = oldname, .newname = newname};
  bpf_map_update_elem(&rename_hash, &pid, &args, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct syscall_trace_enter* ctx) {
  return on_sys_enter_rename((const char*)ctx->args[0],
                             (const char*)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct syscall_trace_enter* ctx) {
  return on_sys_enter_rename((const char*)ctx->args[1],
                             (const char*)ctx->args[3]);
}

static __always_inline
int on_sys_exit_rename(struct syscall_trace_exit* ctx) {
  const uint64_t pid = bpf_get_current_pid_tgid();
  struct rename_args_t* args = bpf_map_lookup_elem(&rename_hash, &pid);
  if (!args) return 0;
  bpf_map_delete_elem(&rename_hash, &pid);
  struct rename_data_t* rename =
      bpf_ringbuf_reserve(&file_rb, sizeof(struct rename_data_t), 0);
  if (!rename) return 0;
  int res = realpath(&rename->new_filename, args->newname);
  /*
  int res = bpf_probe_read_user_str(
      &rename->new_filename, sizeof(rename->new_filename), args->newname);
  */
  if (res < 0 ||
      fill_file_data(&rename->data, args->oldname, ctx->ret, RENAME) < 0) {
    bpf_ringbuf_discard(rename, 0);
    return 0;
  }
  rename->offset = res;
  bpf_ringbuf_submit(rename, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int tracepoint__syscalls__sys_exit_rename(struct syscall_trace_exit* ctx) {
  return on_sys_exit_rename(ctx);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int tracepoint__syscalls__sys_exit_renameat2(struct syscall_trace_exit* ctx) {
  return on_sys_exit_rename(ctx);
}

struct chown_args_t {
  const char* filename;
  uid_t uid;
  gid_t gid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, uint64_t);
	__type(value, struct chown_args_t);
} chown_hash SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fchownat")
int tracepoint__syscalls__sys_enter_fchownat(struct syscall_trace_enter* ctx) {
  uint64_t pid = bpf_get_current_pid_tgid();
  struct chown_args_t args = {.filename = (const char*)ctx->args[1],
                              .uid = (uid_t)ctx->args[2],
                              .gid = (gid_t)ctx->args[3]};
  bpf_map_update_elem(&chown_hash, &pid, &args, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int tracepoint__syscalls__sys_exit_fchownat(struct syscall_trace_exit* ctx) {
  uint64_t pid = bpf_get_current_pid_tgid();
  struct chown_args_t* args = bpf_map_lookup_elem(&chown_hash, &pid);
  if (!args) return 0;
  bpf_map_delete_elem(&chown_hash, &pid);
  struct chown_data_t* chown =
      bpf_ringbuf_reserve(&file_rb, sizeof(struct chown_data_t), 0);
  if (!chown) return 0;
  if (fill_file_data(&chown->data, args->filename, ctx->ret, CHOWN) < 0) {
    bpf_ringbuf_discard(chown, 0);
    return 0;
  }
  chown->setuid = args->uid;
  chown->setgid = args->gid;
  bpf_ringbuf_submit(chown, 0);
  return 0;
}

struct chmod_args_t {
  const char* filename;
  umode_t mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, uint64_t);
	__type(value, struct chmod_args_t);
} chmod_hash SEC(".maps");

static __always_inline
int on_sys_enter_chmod(const char* filename, umode_t mode) {
  uint64_t pid = bpf_get_current_pid_tgid();
  struct chmod_args_t args = {.filename = filename, .mode = mode};
  bpf_map_update_elem(&chmod_hash, &pid, &args, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((const char*)ctx->args[0], (umode_t)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((const char*)ctx->args[1], (umode_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int tracepoint__syscalls__sys_enter_fchmodat2(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((const char*)ctx->args[1], (umode_t)ctx->args[2]);
}

static __always_inline
int on_sys_exit_chmod(struct syscall_trace_exit* ctx) {
  uint64_t pid = bpf_get_current_pid_tgid();
  struct chmod_args_t* args = bpf_map_lookup_elem(&chmod_hash, &pid);
  if (!args) return 0;
  bpf_map_delete_elem(&chmod_hash, &pid);
  struct chmod_data_t* chmod =
      bpf_ringbuf_reserve(&file_rb, sizeof(struct chmod_data_t), 0);
  if (!chmod) return 0;
  if (fill_file_data(&chmod->data, args->filename, ctx->ret, CHMOD) < 0) {
    bpf_ringbuf_discard(chmod, 0);
    return 0;
  }
  chmod->mode = args->mode;
  bpf_ringbuf_submit(chmod, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int tracepoint__syscalls__sys_exit_chmod(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int tracepoint__syscalls__sys_exit_fchmodat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat2")
int tracepoint__syscalls__sys_exit_fchmodat2(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod(ctx);
}

#endif  // LOGGING_FILE_BPF_H_
