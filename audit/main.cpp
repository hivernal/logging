#include <getopt.h>

#include <iostream>

#include "audit/bpf.h"

class Args {
 public:
  Args() = default;
  Args(int argc, char* argv[]) {
    int ch{};
    int longindex{-1};
    while ((ch = getopt_long(argc, argv, "u:p:h:d:", options_, &longindex)) !=
           -1) {
      if (longindex == -1) {
        switch (static_cast<char>(ch)) {
          case 'u':
            user_ = optarg;
            break;
          case 'p':
            pass_ = optarg;
            break;
          case 'h':
            url_ += optarg;
            break;
          case 'd':
            database_ = optarg;
            break;
        }
        continue;
      }
      switch (longindex) {
        case kFileIncludePaths:
          file_include_paths_.push_back(optarg);
          break;
        case kFileExcludePaths:
          file_exclude_paths_.push_back(optarg);
          break;
      }
      longindex = -1;
    }
  }
  ~Args() = default;
  const std::string& Url() { return url_; }
  const std::string& User() { return user_; }
  const std::string& Pass() { return pass_; }
  const std::string& Database() { return database_; }
  std::vector<std::string>&& FileIncludePaths() {
    return std::move(file_include_paths_);
  }
  std::vector<std::string>&& FileExcludePaths() {
    return std::move(file_exclude_paths_);
  }

 private:
  enum Options { kFileIncludePaths, kFileExcludePaths };
  std::string url_{"tcp://"};
  std::string user_{};
  std::string pass_{};
  std::string database_{};
  std::vector<std::string> file_include_paths_{};
  std::vector<std::string> file_exclude_paths_{};
  struct option options_[3] = {{"file_include_path", 1, NULL, 0},
                               {"file_exclude_path", 1, NULL, 0},
                               {NULL, 0, NULL, 0}};
};

int main(int argc, char* argv[]) try {
  Args args{argc, argv};
  audit::Bpf bpf{args.Url(), args.User(), args.Pass(), args.Database()};
  bpf.SetFileIncludePaths(args.FileIncludePaths());
  bpf.SetFileExcludePaths(args.FileExcludePaths());
  int err{0};
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
