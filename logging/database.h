#ifndef LOGGING_DATABASE_H_
#define LOGGING_DATABASE_H_

#include <memory>
#include <sstream>
#include <string_view>

#include "pqxx/pqxx"

namespace logging_audit {

class DataBase {
 public:
  DataBase() = default;
  DataBase(std::string_view url, std::string_view user, std::string_view pass,
           std::string_view database);
  DataBase(const DataBase&) = delete;
  DataBase& operator=(const DataBase&) = delete;
  DataBase(DataBase&&) = delete;
  DataBase& operator=(DataBase&&) = delete;
  virtual ~DataBase();
  void Connect(std::string_view url, std::string_view user,
               std::string_view pass, std::string_view database);
  pqxx::result Execute(pqxx::zview query);
  pqxx::result ExecuteQuery(std::string_view query);
  void Commit();

  template <typename... Args>
  pqxx::result ExecParams0(pqxx::zview query, Args&&... args) {
    return transaction_->exec_params0(query, args...);
  }

 private:
  std::unique_ptr<pqxx::connection> connection_{};
  std::unique_ptr<pqxx::work> transaction_{};
};

}  // namespace logging_audit

#endif  // LOGGING_DATABASE_H_
