#include "audit/database.h"

#include <sstream>

namespace audit {

DataBase::DataBase(std::string_view url, std::string_view user,
                   std::string_view pass, std::string_view database)
    : url_{url},
      user_{user},
      pass_{pass},
      database_{database},
      driver_{sql::mysql::get_driver_instance()},
      connection_{driver_->connect(url_, user_, pass_)},
      statement_{connection_->createStatement()}

{
  connection_->setSchema(database_);
}

bool DataBase::IsValid() const { return connection_ && connection_->isValid(); }

void DataBase::Close() const {
  if (connection_) {
    connection_->close();
  }
}

void DataBase::Connect(std::string_view url, std::string_view user,
                       std::string_view pass, std::string_view database) {
  Close();
  url_ = url;
  user_ = user;
  pass_ = pass;
  database_ = database;
  driver_ = sql::mysql::get_driver_instance();
  connection_ =
      std::unique_ptr<sql::Connection>{driver_->connect(url_, user_, pass_)};
  statement_ = std::unique_ptr<sql::Statement>{connection_->createStatement()};
  connection_->setSchema(database_);
}

bool DataBase::Reconnect() const { return connection_->reconnect(); }

std::unique_ptr<sql::PreparedStatement> DataBase::PreparedStatement(
    const std::string& statement) const {
  return std::unique_ptr<sql::PreparedStatement>{
      connection_->prepareStatement(statement)};
}

std::unique_ptr<sql::ResultSet> DataBase::ExecuteQuery(
    const std::string& query) const {
  return std::unique_ptr<sql::ResultSet>{statement_->executeQuery(query)};
}

bool DataBase::Execute(const std::string& query) const {
  return statement_->execute(query);
}

}  // namespace audit
