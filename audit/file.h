#ifndef AUDIT_FILE_H_
#define AUDIT_FILE_H_

#include "bpf_consts.h"

#define O_WRONLY 000000001
#define O_CREAT 000000100
#define O_TRUNC 000001000
#define O_APPEND 000002000
#define O_TMPFILE 020000000
#define O_RDWR 000000002

enum file_operation_t { OPENAT, UNLINK, MKDIR, RENAME, CHOWN, CHMOD };

struct file_data_t {
  char filename[PATH_MAX];
  char comm[TASK_COMM_LEN];
  uint64_t time_nsec;
  uid_t uid;
  pid_t pid;
  int offset;
  int ret;
  enum file_operation_t operation;
};

struct rename_data_t {
  struct file_data_t data;
  char new_filename[PATH_MAX];
  int offset;
};

struct chown_data_t {
  struct file_data_t data;
  uid_t setuid;
  gid_t setgid;
};

struct chmod_data_t {
  struct file_data_t data;
  unsigned mode;
};

#endif  // AUDIT_FILE_H_
