#include <iostream>

#include "audit/bpf.h"

int main(int argc, char* argv[]) try {
  audit::Bpf bpf{"172.20.0.2", "client_user", "client", "audit"};
  // audit::Bpf bpf{};
  int err = 0;
  while (bpf.Run()) {
    err = bpf.Poll(100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      std::cout << "Error polling perf buffer: " << err << '\n';
      break;
    }
  }
  return err;
} catch (const std::exception& e) {
  std::cerr << e.what() << '\n';
  return 0;
}
