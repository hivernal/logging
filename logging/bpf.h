#ifndef LOGGING_BPF_H_
#define LOGGING_BPF_H_

#include <bpf/libbpf.h>

#include <string>
#include <string_view>

#include "logging/logging.skel.h"
#include "logging/logging.h"
#include "logging/audit_database.h"

namespace logging_audit {

class Bpf {
 public:
  static Bpf& Instance();
  static Bpf& Instance(std::string_view url, std::string_view user,
                       std::string_view pass, std::string_view database);
  Bpf(const Bpf&) = delete;
  Bpf& operator=(const Bpf&) = delete;
  Bpf(Bpf&&) = delete;
  Bpf& operator=(Bpf&&) = delete;
  int Poll(int time_nsec);
  bool Run();
  void SetFileIncludePaths(std::vector<std::string>&& files_include);
  void SetFileExcludePaths(std::vector<std::string>&& files_exclude);

 private:
  Bpf();
  Bpf(std::string_view url, std::string_view user, std::string_view pass,
      std::string_view database);
  ~Bpf();
  static int SetuidHandle(void* ctx, void* data, size_t data_sz);
  static int ExecveHandle(void* ctx, void* data, size_t data_sz);
  static int ExitHandle(void* ctx, void* data, size_t data_sz);
  static int FileHandle(void* ctx, void* data, size_t data_sz);
  static bool ExcludePath(const std::string& pathname);
  static int RenameHandle(const char* filename,
                          const struct rename_data_t* rename, bool exclude);
  static int TcpHandle(void* ctx, void* data, size_t data_sz);
  static void SigHandle(int sig);

  static Bpf* instance_;
  static AuditDataBase db_;
  static bool run_;
  static std::vector<std::string> file_include_paths_;
  static std::vector<std::string> file_exclude_paths_;
  struct logging_bpf* skel_{nullptr};
  struct ring_buffer* setuid_rb_{nullptr};
  struct ring_buffer* file_rb_{nullptr};
  struct ring_buffer* execve_rb_{nullptr};
  struct ring_buffer* exit_rb_{nullptr};
  struct ring_buffer* tcp_rb_{nullptr};
};

}  // namespace logging

#endif  // LOGGING_BPF_H_
