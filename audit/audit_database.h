#ifndef AUDIT_AUDIT_DATABASE_H_
#define AUDIT_AUDIT_DATABASE_H_

#include <unistd.h>

#include <cstdint>
#include <map>
#include <set>

#include "audit/audit.h"
#include "audit/database.h"

namespace audit {

class AuditDataBase : public DataBase {
 public:
  AuditDataBase();
  AuditDataBase(std::string_view url, std::string_view user,
                std::string_view pass, std::string_view database);
  AuditDataBase(const AuditDataBase&) = delete;
  AuditDataBase& operator=(const AuditDataBase&) = delete;
  AuditDataBase(AuditDataBase&&) = delete;
  AuditDataBase& operator=(AuditDataBase&&) = delete;
  ~AuditDataBase() = default;
  std::uint32_t HostID();
  void Sync();
  void AddSetuid(const struct setuid_data_t* data);
  void AddExecve(const struct execve_data_t* data);
  void AddExit(const struct exit_data_t* data);
  void AddFile(const std::string& operation, const struct file_data_t* file,
               const char* filename, const char* argv);
  void AddTcp(const std::string& operation, const struct tcp_data_t* tcp,
              const std::string& source_ip, std::uint16_t source_port,
              const std::string& dest_ip, std::uint16_t dest_port);

 private:
  const std::string kHostIDFilename{"/etc/audit_host_id"};
  const std::uint32_t kHostID{};

  struct UserInfo {
    std::string name{};
    std::set<gid_t> gids{};
  };

  struct UsersGroupsInfo {
    std::map<gid_t, std::string> groups{};
    std::map<uid_t, UserInfo> users{};
  };

  struct DataBaseUsersGroupsInfo : UsersGroupsInfo {
    std::set<uid_t> users_enabled{};
    std::set<gid_t> groups_enabled{};
  };

  void AddHost();
  AuditDataBase::UsersGroupsInfo GetLocalUsersGroupsInfo();
  AuditDataBase::DataBaseUsersGroupsInfo GetDataBaseUsersGroupsInfo();
  void DeleteUsers(const std::map<uid_t, UserInfo>& users);
  void DeleteGroups(const std::map<uid_t, std::string>& groups);
  void DeleteUsersGroups(const std::map<uid_t, UserInfo>& users);
  void AddChangeUsers(const UsersGroupsInfo& local_info,
                      const DataBaseUsersGroupsInfo& db_info);
  void AddChangeGroups(const UsersGroupsInfo& local_info,
                       const DataBaseUsersGroupsInfo& db_info);
  void AddUsersGroups(const UsersGroupsInfo& local_info,
                      const DataBaseUsersGroupsInfo& db_info);
};

}  // namespace audit

#endif  // AUDIT_AUDIT_DATABASE_H_
