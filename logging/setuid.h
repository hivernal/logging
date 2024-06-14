#ifndef LOGGING_SETUID_H_
#define LOGGING_SETUID_H_

#include "bpf_consts.h"

struct setuid_data_t {
  char comm[TASK_COMM_LEN];
  uint64_t time_nsec;
  uid_t uid;
  uid_t setuid;
  pid_t pid;
  int ret;
};

#endif  // LOGGING_SETUID_H_
