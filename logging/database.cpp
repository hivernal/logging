#include "logging/database.h"

#include <sstream>

namespace logging_audit {

std::string FillOptions(std::string_view url, std::string_view user,
                        std::string_view pass, std::string_view database) {
  std::string options{"postgresql://"};
  options += user;
  options += ':';
  options += pass;
  options += '@';
  options += url;
  options += '/';
  options += database;
  return options;
}

DataBase::DataBase(std::string_view url, std::string_view user,
                   std::string_view pass, std::string_view database)
    : connection_{new pqxx::connection{
          FillOptions(url, user, pass, database).c_str()}},
      transaction_{new pqxx::work{*connection_}} {}

DataBase::~DataBase() { transaction_->commit(); }

void DataBase::Connect(std::string_view url, std::string_view user,
                       std::string_view pass, std::string_view database) {
  connection_ = std::make_unique<pqxx::connection>(
      FillOptions(url, user, pass, database).c_str());
  transaction_ = std::make_unique<pqxx::work>(*connection_);
}

void DataBase::Commit() { transaction_->commit(); }

pqxx::result DataBase::Execute(pqxx::zview query) {
  return transaction_->exec0(query);
}

pqxx::result DataBase::ExecuteQuery(std::string_view query) {
  return transaction_->exec(query);
};

}  // namespace logging
