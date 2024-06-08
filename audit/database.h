#ifndef AUDIT_DATABASE_H_
#define AUDIT_DATABASE_H_

#include <memory>
#include <string>
#include <string_view>

#include "mysql/include/mysql/jdbc.h"

namespace audit {

class DataBase {
 public:
  DataBase() = default;
  DataBase(std::string_view url, std::string_view user, std::string_view pass,
           std::string_view database);
  DataBase(const DataBase&) = delete;
  DataBase& operator=(const DataBase&) = delete;
  DataBase(DataBase&&) = delete;
  DataBase& operator=(DataBase&&) = delete;
  virtual ~DataBase() = default;
  bool IsValid() const;
  void Close() const;
  void Connect(std::string_view url, std::string_view user,
               std::string_view pass, std::string_view database);
  bool Reconnect() const;
  bool Execute(const std::string& query) const;
  std::unique_ptr<sql::PreparedStatement> PreparedStatement(
      const std::string& statement) const;
  std::unique_ptr<sql::ResultSet> ExecuteQuery(const std::string& query) const;

 private:
  std::string url_{};
  std::string user_{};
  std::string pass_{};
  std::string database_{};
  sql::Driver* driver_{};
  std::unique_ptr<sql::Connection> connection_{};
  std::unique_ptr<sql::Statement> statement_{};
};

}  // namespace audit
#endif  // AUDIT_DATABASE_H_
