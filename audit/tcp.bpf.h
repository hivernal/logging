#ifndef AUDIT_TCP_BPF_H_
#define AUDIT_TCP_BPF_H_

#include "tcp.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, struct sock*);
  __type(value, struct tcp_info_t);
} tcp_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} tcp_rb SEC(".maps");

static __always_inline
int fill_tcp_info(struct tcp_info_t* data, struct sock* sk,
                  enum tcp_version_t version, enum tcp_operation_t operation) {
  data->version = version;
  data->operation = operation;
  data->time_nsec = bpf_ktime_get_tai_ns();
  data->uid = (uid_t)bpf_get_current_uid_gid();
  data->pid = (pid_t)bpf_get_current_pid_tgid();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock* sk) {
  struct tcp_info_t data;
  fill_tcp_info(&data, sk, IPV4, CONNECT);
  bpf_map_update_elem(&tcp_hash, &sk, &data, 0);
  return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock* sk) {
  struct tcp_info_t data;
  fill_tcp_info(&data, sk, IPV6, CONNECT);
  bpf_map_update_elem(&tcp_hash, &sk, &data, 0);
  return 0;
}

static __always_inline
int fill_tcp_ports(uint16_t* lport, uint16_t* dport, struct sock* sk) {
  int res = bpf_core_read(lport, sizeof(*lport), &sk->__sk_common.skc_num);
  if (res < 0) return -1;
  res = bpf_core_read(dport, sizeof(*dport), &sk->__sk_common.skc_dport);
  if (res < 0) return -1;
  return 0;
}

static __always_inline
int fill_tcp_v4_data(struct tcp_v4_data_t* tcp_v4, struct sock* sk) {
  int res = bpf_core_read(&tcp_v4->saddr, sizeof(tcp_v4->saddr),
                          &sk->__sk_common.skc_rcv_saddr);
  if (res < 0) return -1;
  res = bpf_core_read(&tcp_v4->daddr, sizeof(tcp_v4->daddr),
                      &sk->__sk_common.skc_daddr);
  if (res < 0) return -1;
  res = fill_tcp_ports(&tcp_v4->lport, &tcp_v4->dport, sk);
  if (res < 0) return -1;
  return 0;
}

static __always_inline
int fill_tcp_v6_data(struct tcp_v6_data_t* tcp_v6, struct sock* sk) {
  int res = bpf_probe_read_kernel(&tcp_v6->saddr, sizeof(tcp_v6->saddr),
                                  sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
  if (res < 0) return -1;
  res = bpf_probe_read_kernel(&tcp_v6->daddr, sizeof(tcp_v6->daddr),
                              sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
  if (res < 0) return -1;
  res = fill_tcp_ports(&tcp_v6->lport, &tcp_v6->dport, sk);
  if (res < 0) return -1;
  return 0;
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock* sk) {
  if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;
  struct tcp_info_t* data = bpf_map_lookup_elem(&tcp_hash, &sk);
  if (!data) return 0;
  if (data->version == IPV4) {
    struct tcp_v4_data_t* tcp_v4 =
        bpf_ringbuf_reserve(&tcp_rb, sizeof(struct tcp_v4_data_t), 0);
    if (!tcp_v4) goto cleanup;
    if (bpf_core_read(&tcp_v4->data, sizeof(tcp_v4->data), data) < 0 ||
        fill_tcp_v4_data(tcp_v4, sk) < 0) {
      bpf_ringbuf_discard(tcp_v4, 0);
      goto cleanup;
    }
    bpf_ringbuf_submit(tcp_v4, 0);
  } else {
    struct tcp_v6_data_t* tcp_v6 =
        bpf_ringbuf_reserve(&tcp_rb, sizeof(struct tcp_v6_data_t), 0);
    if (!tcp_v6) goto cleanup;
    int res = bpf_core_read(&tcp_v6->data, sizeof(tcp_v6->data), data);
    if (bpf_core_read(&tcp_v6->data, sizeof(tcp_v6->data), data) < 0 ||
        fill_tcp_v6_data(tcp_v6, sk) < 0) {
      bpf_ringbuf_discard(tcp_v6, 0);
      goto cleanup;
    }
    bpf_ringbuf_submit(tcp_v6, 0);
  }
cleanup:
  bpf_map_delete_elem(&tcp_hash, &sk);
  return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock* sk) {
  if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET) {
    struct tcp_v4_data_t* tcp_v4 =
        bpf_ringbuf_reserve(&tcp_rb, sizeof(struct tcp_v4_data_t), 0);
    if (!tcp_v4) return 0;
    fill_tcp_info(&tcp_v4->data, sk, IPV4, ACCEPT);
    if (fill_tcp_v4_data(tcp_v4, sk)) {
      bpf_ringbuf_discard(tcp_v4, 0);
      return 0;
    }
    bpf_ringbuf_submit(tcp_v4, 0);
  } else {
    struct tcp_v6_data_t* tcp_v6 =
        bpf_ringbuf_reserve(&tcp_rb, sizeof(struct tcp_v6_data_t), 0);
    if (!tcp_v6) return 0;
    fill_tcp_info(&tcp_v6->data, sk, IPV6, ACCEPT);
    if (fill_tcp_v6_data(tcp_v6, sk)) {
      bpf_ringbuf_discard(tcp_v6, 0);
      return 0;
    }
    bpf_ringbuf_submit(tcp_v6, 0);
  }
  return 0;
}

#endif  // AUDIT_TCP_BPF_H_
