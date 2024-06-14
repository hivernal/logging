#ifndef LOGGING_COMMON_BPF_H_
#define LOGGING_COMMON_BPF_H_

#include "bpf_consts.h"

/*
static __always_inline
int get_full_path(char path[PATH_MAX], const struct dentry* dentry) {
  if (!path || !dentry) return -1;
  unsigned buf_off = (PATH_MAX >> 1);
#pragma unroll
  for (int i = 0; i < MAX_DENTRY_DEPTH; ++i) {
    int res = -1;
    const struct dentry* new_dentry = NULL;
    res = bpf_core_read(&new_dentry, sizeof(new_dentry), &dentry->d_parent);
    if (res < 0) return -1;
    if (dentry == new_dentry) break;

    struct qstr qstr;
    res = bpf_core_read(&qstr, sizeof(qstr), &dentry->d_name);
    if (res < 0) return -1;
    const unsigned len = (qstr.len + 1) & ((PATH_MAX >> 1) - 1);
    if (len > buf_off) return -1;
    const unsigned off = buf_off - len;
    res = bpf_probe_read_str(&path[off & ((PATH_MAX >> 1) - 1)], len,
                             qstr.name);
    if (res > 1) {
      buf_off -= 1;
      path[buf_off & ((PATH_MAX >> 1) - 1)] = '/';
      buf_off -= res - 1;
    } else if (res < 0 || res == 1){
      return -1;
    }

    res = bpf_core_read(&dentry, sizeof(dentry), &new_dentry);
    if (res < 0) return -1;
  }
  if (buf_off != 0) {
    buf_off -= 1;
    path[buf_off & ((PATH_MAX >> 1) - 1)] = '/';
  }
  path[PATH_MAX >> 1] = '\0';
  return (int)buf_off;
}

static __always_inline
int get_full_path_v2(void* ptr, const struct dentry* dentry) {
  char* path = ptr;
  if (!path || !dentry) return -1;
  unsigned buf_off = PATH_MAX - 1;
  path[buf_off] = '\0';
#pragma unroll
  for (int i = 0; i < MAX_DENTRY_DEPTH; ++i) {
    const struct dentry* new_dentry = NULL;
    int res = bpf_core_read(&new_dentry, sizeof(new_dentry), &dentry->d_parent);
    if (res < 0) return buf_off;
    if (dentry == new_dentry) break;

    struct qstr qstr;
    res = bpf_core_read(&qstr, sizeof(qstr), &dentry->d_name);
    if (res < 0) return buf_off;
    unsigned len = qstr.len + 1;
    const unsigned off = buf_off - len;
    len &= (PATH_MAX >> 1) - 1;
    if (off > PATH_MAX - len) return buf_off;
    res = bpf_core_read_str(&path[off], len, qstr.name);
    if (res < 0 || res == 1) return buf_off;
    buf_off -= 1;
    if (buf_off  > PATH_MAX - 1) return buf_off;
    path[buf_off] = '/';
    if (buf_off < res - 1) return buf_off;
    buf_off -= res - 1;

    res = bpf_core_read(&dentry, sizeof(dentry), &new_dentry);
    if (res < 0) return buf_off;
  }
  if (buf_off != 0 && buf_off <= PATH_MAX) {
    buf_off -= 1;
    path[buf_off] = '/';
  }
  return (int)buf_off;
}
*/

static __always_inline
int get_full_path_v3(void* ptr, const struct dentry* dentry) {
  char* path = ptr;
  if (!path || !dentry) return -1;
  const char* names[MAX_DENTRY_DEPTH];
  int res = 0;
  int i;
#pragma unroll
  for (i = 0; i < MAX_DENTRY_DEPTH; ++i) {
    const struct dentry* new_dentry = NULL;
    res = bpf_core_read(&new_dentry, sizeof(new_dentry), &dentry->d_parent);
    if (res < 0) return -1;
    if (dentry == new_dentry) {
      --i;
      break;
    }
    res = bpf_core_read(&names[i], sizeof(names[i]), &dentry->d_name.name);
    if (res < 0) return -1;
    res = bpf_core_read(&dentry, sizeof(dentry), &new_dentry);
    if (res < 0) return -1;
  }

  unsigned count = 1;
  path[0] = '/';
  for(; i >= 0; --i) {
    if (count > PATH_MAX - 256) return (int)count;
    res = bpf_probe_read_kernel_str(&path[count], 256, names[i]);
    if (res <= 0) return (int)count;
    count += res - 1;
    if (count > PATH_MAX - 1) return (int)count;
    path[count] = '/';
    ++count;
  }
  if (count == PATH_MAX) return (int)count;
  path[count & (PATH_MAX - 1)] = '\0';
  return (int)count;
}

#endif  // LOGGING_COMMON_BPF_H_
