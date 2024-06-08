#ifndef AUDIT_PROCESS_H_
#define AUDIT_PROCESS_H_

#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct execve_data_t {
  char pwd[PATH_MAX];
  char argv[FULL_MAX_ARGS_ARR];
  uint64_t time_nsec;
  uid_t uid;
  pid_t pid;
  pid_t ppid;
  int pwd_size;
  int ret;
  char comm[TASK_COMM_LEN];
};

struct exit_data_t {
  char comm[TASK_COMM_LEN];
  uint64_t time_nsec;
  uid_t uid;
  pid_t pid;
  int code;
};

#endif  // AUDIT_PROCESS_H_
