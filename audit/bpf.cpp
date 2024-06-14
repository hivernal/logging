#include "audit/bpf.h"

#include <arpa/inet.h>
#include <signal.h>
#include <sys/resource.h>

#include <iostream>
#include <limits>
#include <sstream>

namespace audit {

AuditDataBase Bpf::db_{};
Bpf* Bpf::instance_{nullptr};
bool Bpf::run_{true};
std::vector<std::string> Bpf::file_include_paths_{};
std::vector<std::string> Bpf::file_exclude_paths_{"/dev/null"};

const char* kCreateRingBufferError{"Failed to open and load BPF skeleton"};
const char* kUnlockMemoryError{"Failed to unlock memory limit"};
const char* kOpenSkeletonError{"Failed to open BPF skeleton"};
const char* kLoadSkeletonError{"Failed to load and verify BPF skeleton"};
const char* kAttachSkeletonError{"Failed to attach BPF skeleton"};

Bpf& Bpf::Instance() {
  if (instance_) {
    return *instance_;
  }
  static Bpf instance{};
  instance_ = &instance;
  return instance;
}

Bpf& Bpf::Instance(std::string_view url, std::string_view user,
                   std::string_view pass, std::string_view database) {
  if (instance_) {
    return *instance_;
  }
  static Bpf instance{url, user, pass, database};
  instance_ = &instance;
  return instance;
}

Bpf::Bpf() {
  struct rlimit rlim {};
  rlim.rlim_cur = 512UL << 20;
  rlim.rlim_max = 512UL << 20;
  int err = setrlimit(RLIMIT_MEMLOCK, &rlim);
  if (err) {
    throw std::runtime_error(kUnlockMemoryError);
    return;
  }
  signal(SIGINT, SigHandle);
  signal(SIGTERM, SigHandle);

  skel_ = audit_bpf__open();
  if (!skel_) {
    throw std::runtime_error(kOpenSkeletonError);
    return;
  }

  err = audit_bpf__load(skel_);
  if (err) {
    throw std::runtime_error(kLoadSkeletonError);
    return;
  }

  err = audit_bpf__attach(skel_);
  if (err) {
    throw std::runtime_error(kAttachSkeletonError);
    return;
  }

  setuid_rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.setuid_rb),
                                SetuidHandle, nullptr, nullptr);
  if (!setuid_rb_) {
    throw std::runtime_error(kCreateRingBufferError);
    return;
  }

  file_rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.file_rb), FileHandle,
                              nullptr, nullptr);
  if (!file_rb_) {
    throw std::runtime_error(kCreateRingBufferError);
    return;
  }

  execve_rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.execve_rb),
                                ExecveHandle, nullptr, nullptr);
  if (!execve_rb_) {
    throw std::runtime_error(kCreateRingBufferError);
    return;
  }

  exit_rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.exit_rb), ExitHandle,
                              nullptr, nullptr);
  if (!exit_rb_) {
    throw std::runtime_error(kCreateRingBufferError);
    return;
  }

  tcp_rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.tcp_rb), TcpHandle,
                             nullptr, nullptr);
  if (!tcp_rb_) {
    throw std::runtime_error(kCreateRingBufferError);
    return;
  }
}

Bpf::Bpf(std::string_view url, std::string_view user, std::string_view pass,
         std::string_view database)
    : Bpf{} {
  db_.Connect(url, user, pass, database);
  db_.Sync();
}

Bpf::~Bpf() {
  ring_buffer__free(setuid_rb_);
  ring_buffer__free(file_rb_);
  ring_buffer__free(execve_rb_);
  ring_buffer__free(exit_rb_);
  ring_buffer__free(tcp_rb_);
  audit_bpf__destroy(skel_);
}

void Bpf::SigHandle([[maybe_unused]] int sig) { run_ = false; }

int Bpf::Poll(int time_nsec) {
  int err = ring_buffer__poll(setuid_rb_, time_nsec);
  err = ring_buffer__poll(execve_rb_, time_nsec);
  err = ring_buffer__poll(exit_rb_, time_nsec);
  err = ring_buffer__poll(tcp_rb_, time_nsec);
  err = ring_buffer__poll(file_rb_, time_nsec);
  return err;
}

bool Bpf::Run() { return run_; }

void Bpf::SetFileIncludePaths(std::vector<std::string>&& file_include) {
  if (file_include.size()) {
    file_include_paths_ = file_include;
  }
}
void Bpf::SetFileExcludePaths(std::vector<std::string>&& file_exclude) {
  if (file_exclude.size()) {
    file_exclude_paths_ = file_exclude;
  }
}

int Bpf::SetuidHandle([[maybe_unused]] void* ctx, void* data,
                      [[maybe_unused]] size_t data_sz) {
  auto setuid{static_cast<const struct setuid_data_t*>(data)};
  db_.AddSetuid(setuid);
  return 0;
}

int Bpf::ExecveHandle([[maybe_unused]] void* ctx, void* data,
                      [[maybe_unused]] size_t data_sz) {
  auto execve{static_cast<const struct execve_data_t*>(data)};
  db_.AddExecve(execve);
  return 0;
}

int Bpf::ExitHandle([[maybe_unused]] void* ctx, void* data,
                    [[maybe_unused]] size_t data_sz) {
  auto exit{static_cast<const struct exit_data_t*>(data)};
  db_.AddExit(exit);
  return 0;
}

bool IsRelative(const char* path) {
  for (; *path != '\0'; ++path) {
    if (*path == '.' && (*(++path) == '.' || *path == '/')) return true;
  }
  return false;
}

std::unique_ptr<char[]> ChmodToChar(mode_t mode) {
  constexpr int chmod_str_size{10};
  std::unique_ptr<char[]> chmod_str{new char[chmod_str_size]};
  if (!chmod_str) return nullptr;
  enum FileFlags {
    kRead = 0400,
    kWrite = 0200,
    kExecute = 0100,
    kSpecial = 04000
  };
  constexpr std::size_t steps{3};
  for (std::size_t i{0}; i < steps; ++i) {
    if (mode & (kRead >> (steps * i))) {
      chmod_str[i * steps] = 'r';
    } else {
      chmod_str[i * steps] = '-';
    }
    if (mode & (kWrite >> (steps * i))) {
      chmod_str[i * steps + 1] = 'w';
    } else {
      chmod_str[i * steps + 1] = '-';
    }
    if (mode & (kExecute >> (i * steps))) {
      if (mode & (kSpecial >> i)) {
        if (i != 2) {
          chmod_str[i * steps + 2] = 's';
        } else {
          chmod_str[i * steps + 2] = 't';
        }
      } else {
        chmod_str[i * steps + 2] = 'x';
      }
    } else if (mode & (kSpecial >> i)) {
      if (i != 2) {
        chmod_str[i * steps + 2] = 'S';
      } else {
        chmod_str[i * steps + 2] = 'T';
      }
    } else {
      chmod_str[i * steps + 2] = '-';
    }
  }
  return chmod_str;
}

std::unique_ptr<char[]> ChownToChar(uid_t uid, gid_t gid) {
  constexpr int chown_str_size{11};
  std::unique_ptr<char[]> chown_str{new char[chown_str_size]};
  if (!chown_str.get()) return nullptr;
  std::size_t offset{0};
  if (uid < std::numeric_limits<uid_t>::max()) {
    offset = static_cast<std::size_t>(std::sprintf(chown_str.get(), "%u", uid));
  }
  chown_str[offset++] = ':';
  if (gid < std::numeric_limits<gid_t>::max()) {
    offset += static_cast<std::size_t>(
        std::sprintf(chown_str.get() + offset, "%u", gid));
  }
  chown_str[offset] = '\0';
  return chown_str;
}

int Bpf::FileHandle([[maybe_unused]] void* ctx, void* data,
                    [[maybe_unused]] size_t data_sz) {
  auto file{static_cast<const struct file_data_t*>(data)};
  char buffer[PATH_MAX];
  const char* filename{IsRelative(file->filename + file->offset)
                           ? (realpath(file->filename, buffer), buffer)
                           : file->filename};
  auto exclude{ExcludePath(filename)};
  if (exclude && file->operation != RENAME) return 0;
  std::string operation{};
  std::unique_ptr<char[]> argv{};
  switch (file->operation) {
    case OPENAT:
      operation = "openat";
      break;
    case UNLINK:
      operation = "unlink";
      break;
    case MKDIR:
      operation = "mkdir";
      break;
    case RENAME:
      return RenameHandle(
          filename, static_cast<const struct rename_data_t*>(data), exclude);
    case CHOWN: {
      operation = "chown";
      auto chown{static_cast<const struct chown_data_t*>(data)};
      argv = ChownToChar(chown->setuid, chown->setgid);
      break;
    }
    case CHMOD: {
      operation = "chmod";
      auto chmod{static_cast<const struct chmod_data_t*>(data)};
      argv = ChmodToChar(chmod->mode);
      break;
    }
  }
  db_.AddFile(operation, file, filename, argv.get());
  return 0;
}

bool Bpf::ExcludePath(const std::string& pathname) {
  for (const auto& path : file_exclude_paths_) {
    if (pathname.find(path) != std::string::npos) {
      return true;
    }
  }
  for (const auto& path : file_include_paths_) {
    if (pathname.find(path) != std::string::npos) {
      return false;
    }
  }
  return true;
}

int Bpf::RenameHandle(const char* filename, const struct rename_data_t* rename,
                      bool exclude) {
  const char* new_filename{rename->new_filename};
  std::unique_ptr<char[]> buffer{};
  if (IsRelative(rename->new_filename + rename->offset)) {
    buffer = std::make_unique<char[]>(PATH_MAX);
    realpath(rename->new_filename, buffer.get());
    new_filename = buffer.get();
  }
  if (!exclude || !ExcludePath(new_filename)) {
    db_.AddFile("rename", &rename->data, filename, new_filename);
  }
  return 0;
}

/*
constexpr std::array kHexCodes{'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string IpV4ToHex(std::uint32_t ipv4) {
  std::string ip_hex{"0x"};
  std::uint32_t mask{0xF};
  auto shift{sizeof(ipv4) * 8 - 4};
  for (std::size_t i{0}; i < sizeof(ipv4) * 8 / 4; ++i) {
    auto index{static_cast<std::size_t>(ipv4 & (mask << shift))};
    index >>= shift;
    ip_hex.push_back(kHexCodes[index]);
    shift -= 4;
  }
  return ip_hex;
}

std::string IpV6ToHex(const std::uint8_t ipv6[16]) {
  std::string ip_hex{"0x"};
  for (int i{0}; i < 16; ++i) {
    ip_hex.push_back(
        kHexCodes[static_cast<std::size_t>((ipv6[i] & 0xF0) >> 4)]);
    ip_hex.push_back(kHexCodes[static_cast<std::size_t>(ipv6[i] & 0x0F)]);
  }
  return ip_hex;
}
*/

int Bpf::TcpHandle([[maybe_unused]] void* ctx, void* data,
                   [[maybe_unused]] size_t data_sz) {
  auto tcp{static_cast<const struct tcp_data_t*>(data)};
  std::string operation{};
  switch (tcp->operation) {
    case ACCEPT:
      operation = "accept";
      break;
    case CONNECT:
      operation = "connect";
      break;
  }
  switch (tcp->version) {
    case IPV4: {
      constexpr std::string::size_type size{16};
      auto tcp_v4{static_cast<const struct tcp_v4_data_t*>(data)};
      std::string saddr(size, '\0');
      inet_ntop(AF_INET, &tcp_v4->saddr, saddr.data(), size);
      std::string daddr(size, '\0');
      inet_ntop(AF_INET, &tcp_v4->daddr, daddr.data(), size);
      db_.AddTcp(operation, tcp, saddr, tcp_v4->lport, daddr,
                 ntohs(tcp_v4->dport));
      break;
    }
    case IPV6: {
      constexpr std::string::size_type size{40};
      auto tcp_v6{static_cast<const struct tcp_v6_data_t*>(data)};
      std::string saddr(size, '\0');
      inet_ntop(AF_INET6, &tcp_v6->saddr, saddr.data(), size);
      std::string daddr(size, '\0');
      inet_ntop(AF_INET6, &tcp_v6->daddr, daddr.data(), size);
      db_.AddTcp(operation, tcp, saddr, tcp_v6->lport, daddr,
                 ntohs(tcp_v6->dport));
      break;
    }
  }
  return 0;
}

}  // namespace audit
