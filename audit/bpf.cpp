#include "audit/bpf.h"

#include <arpa/inet.h>
#include <signal.h>
#include <sys/resource.h>

#include <limits>
#include <sstream>

namespace audit {

AuditDataBase Bpf::db_;
bool Bpf::run_ = true;

const char* kCreateRingBufferError{"Failed to open and load BPF skeleton"};
const char* kUnlockMemoryError{"Failed to unlock memory limit"};
const char* kOpenSkeletonError{"Failed to open BPF skeleton"};
const char* kLoadSkeletonError{"Failed to load and verify BPF skeleton"};
const char* kAttachSkeletonError{"Failed to attach BPF skeleton"};

Bpf::Bpf() {
  struct rlimit rlim = {
      .rlim_cur = 512UL << 20,
      .rlim_max = 512UL << 20,
  };
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

int Bpf::SetuidHandle([[maybe_unused]] void* ctx, void* data,
                      [[maybe_unused]] size_t data_sz) {
  auto event{static_cast<const struct setuid_data_t*>(data)};
  db_.AddSetuid(event);
  return 0;
}

int Bpf::ExecveHandle([[maybe_unused]] void* ctx, void* data,
                      [[maybe_unused]] size_t data_sz) {
  auto event{static_cast<const struct execve_data_t*>(data)};
  db_.AddExecve(event);
  return 0;
}

int Bpf::ExitHandle([[maybe_unused]] void* ctx, void* data,
                    [[maybe_unused]] size_t data_sz) {
  auto event{static_cast<const struct exit_data_t*>(data)};
  db_.AddExit(event);
  return 0;
}

bool IsRelative(const char* path) {
  for (; *path != '\0'; ++path) {
    if (*path == '.' && (*(++path) == '.' || *path == '/')) return true;
  }
  return false;
}

char* ChmodToChar(mode_t mode) {
  constexpr int chmod_str_size{10};
  char* chmod_str = new char[chmod_str_size];
  if (!chmod_str) return nullptr;
  enum FileFlags {
    kRead = 0400,
    kWrite = 0200,
    kExecute = 0100,
    kSpecial = 04000
  };
  constexpr int steps{3};
  for (int i{0}; i < steps; ++i) {
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

char* ChownToChar(uid_t uid, gid_t gid) {
  constexpr int chown_str_size{11};
  char* chown_str{new char[chown_str_size]};
  if (!chown_str) return nullptr;
  int offset{0};
  if (uid < std::numeric_limits<uid_t>::max()) {
    offset = std::sprintf(chown_str, "%u", uid);
  }
  chown_str[offset++] = ':';
  if (gid < std::numeric_limits<gid_t>::max()) {
    offset += std::sprintf(chown_str + offset, "%u", gid);
  }
  chown_str[offset] = '\0';
  return chown_str;
}

int Bpf::FileHandle([[maybe_unused]] void* ctx, void* data,
                    [[maybe_unused]] size_t data_sz) {
  auto file{static_cast<struct file_data_t*>(data)};
  char buffer[PATH_MAX];
  char* filename{IsRelative(file->filename)
                     ? (realpath(file->filename, buffer), buffer)
                     : file->filename};
  std::string operation{};
  char* argv{nullptr};
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
    case RENAME: {
      operation = "rename";
      auto rename{static_cast<struct rename_data_t*>(data)};
      if (IsRelative(rename->new_filename + rename->offset)) {
        char* buffer{new char[PATH_MAX]};
        realpath(rename->new_filename, buffer);
        argv = buffer;
        break;
      } else {
        db_.AddFile(operation, file, filename, rename->new_filename);
        return 0;
      }
    }
    case CHOWN: {
      operation = "chown";
      auto chown{static_cast<struct chown_data_t*>(data)};
      argv = ChownToChar(chown->setuid, chown->setgid);
      break;
    }
    case CHMOD: {
      operation = "chmod";
      auto chmod{static_cast<struct chmod_data_t*>(data)};
      argv = ChmodToChar(chmod->mode);
      break;
    }
  }
  db_.AddFile(operation, file, filename, argv);
  delete argv;
  return 0;
}

constexpr std::array kHexCodes{'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string IpV4ToHex(std::uint32_t ipv4) {
  std::string ip_hex{"0x"};
  std::uint32_t mask{0xF};
  auto shift{sizeof(ipv4) * 8 - 4};
  for (int i{0}; i < sizeof(ipv4) * 8 / 4; ++i) {
    std::size_t index{static_cast<std::size_t>(ipv4 & (mask << shift))};
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

int Bpf::TcpHandle([[maybe_unused]] void* ctx, void* data,
                   [[maybe_unused]] size_t data_sz) {
  auto tcp{static_cast<const struct tcp_info_t*>(data)};
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
      auto tcp_v4{static_cast<const struct tcp_v4_data_t*>(data)};
      db_.AddTcp(operation, tcp, IpV4ToHex(htonl(tcp_v4->saddr)), tcp_v4->lport,
                 IpV4ToHex(htonl(tcp_v4->daddr)), ntohs(tcp_v4->dport));
      break;
    }
    case IPV6: {
      auto tcp_v6{static_cast<const struct tcp_v6_data_t*>(data)};
      db_.AddTcp(operation, tcp, IpV6ToHex(tcp_v6->saddr), tcp_v6->lport,
                 IpV6ToHex(tcp_v6->daddr), ntohs(tcp_v6->dport));
      break;
    }
  }
  return 0;
}

void Bpf::SigHandle(int sig) { run_ = false; }

int Bpf::Poll(int time_nsec) {
  int err = ring_buffer__poll(setuid_rb_, time_nsec);
  err = ring_buffer__poll(execve_rb_, time_nsec);
  err = ring_buffer__poll(exit_rb_, time_nsec);
  err = ring_buffer__poll(tcp_rb_, time_nsec);
  err = ring_buffer__poll(file_rb_, time_nsec);
  return err;
}

bool Bpf::Run() { return run_; }

}  // namespace audit
