#ifndef AUDIT_BPF_H_
#define AUDIT_BPF_H_

#include <bpf/libbpf.h>

#include <string>
#include <string_view>

#include "audit/audit.h"
#include "audit/audit.skel.h"
#include "audit/audit_database.h"

namespace audit {

class Bpf {
 public:
  Bpf();
  Bpf(std::string_view url, std::string_view user, std::string_view pass,
      std::string_view database);
  Bpf(const Bpf&) = delete;
  Bpf& operator=(const Bpf&) = delete;
  Bpf(Bpf&&) = delete;
  Bpf& operator=(Bpf&&) = delete;
  ~Bpf();
  int Poll(int time_nsec);
  bool Run();
  void SetFileIncludePaths(std::vector<std::string>&& files_include);
  void SetFileExcludePaths(std::vector<std::string>&& files_exclude);

 private:
  static int SetuidHandle(void* ctx, void* data, size_t data_sz);
  static int ExecveHandle(void* ctx, void* data, size_t data_sz);
  static int ExitHandle(void* ctx, void* data, size_t data_sz);
  static int FileHandle(void* ctx, void* data, size_t data_sz);
  static int TcpHandle(void* ctx, void* data, size_t data_sz);
  static void SigHandle(int sig);

  static AuditDataBase db_;
  static bool run_;
  static std::vector<std::string> file_include_paths_;
  static std::vector<std::string> file_exclude_paths_;
  struct audit_bpf* skel_{nullptr};
  struct ring_buffer* setuid_rb_{nullptr};
  struct ring_buffer* file_rb_{nullptr};
  struct ring_buffer* execve_rb_{nullptr};
  struct ring_buffer* exit_rb_{nullptr};
  struct ring_buffer* tcp_rb_{nullptr};
};

}  // namespace audit

#endif  // AUDIT_BPF_H_
