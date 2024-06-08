#ifndef AUDIT_TCP_H_
#define AUDIT_TCP_H_

#include "bpf_consts.h"

#ifndef AF_INET
#define AF_INET 2
#endif  // AF_INET

enum tcp_version_t { IPV4, IPV6 };
enum tcp_operation_t { CONNECT, ACCEPT };

struct tcp_info_t {
  char comm[TASK_COMM_LEN];
  uint64_t time_nsec;
  uid_t uid;
  pid_t pid;
  enum tcp_version_t version;
  enum tcp_operation_t operation;
};

struct tcp_v4_data_t {
  struct tcp_info_t data;
  uint32_t saddr;
  uint32_t daddr;
  uint16_t lport;
  uint16_t dport;
};

struct tcp_v6_data_t {
  struct tcp_info_t data;
  uint8_t saddr[16];
  uint8_t daddr[16];
  uint16_t lport;
  uint16_t dport;
};

#endif  // AUDIT_TCP_H_
