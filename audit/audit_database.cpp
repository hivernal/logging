#include "audit/audit_database.h"

#include <arpa/inet.h>
#include <grp.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pwd.h>

#include <climits>
#include <fstream>
#include <random>
#include <sstream>

namespace audit {

std::uint32_t GetHostID(const std::string& filename) {
  std::ifstream file_in{filename};
  if (!file_in.good()) {
    std::ofstream file_out{filename};
    if (!file_out.good()) {
      return 0;
    }
    std::mt19937 mt{std::random_device{}()};
    std::uint32_t host_id{static_cast<std::uint32_t>(mt())};
    file_out << host_id;
    return host_id;
  } else {
    std::uint32_t host_id;
    file_in >> host_id;
    file_in.close();
    return host_id;
  }
}

struct HostIP {
  std::uint32_t ip;
  std::uint32_t netmask;
  std::string ifa_name;
};

std::vector<HostIP> GetHostIPs() {
  std::vector<HostIP> ifas_info{};
  struct ifaddrs *ifap, *ifa;
  getifaddrs(&ifap);
  constexpr std::uint32_t localhost{0x7F};
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_netmask && ifa->ifa_name &&
        ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in* sockaddr = (struct sockaddr_in*)ifa->ifa_addr;
      std::uint32_t ip{sockaddr->sin_addr.s_addr};
      if ((ip & localhost) == localhost) continue;
      sockaddr = (struct sockaddr_in*)ifa->ifa_netmask;
      std::uint32_t netmask{sockaddr->sin_addr.s_addr};
      ifas_info.push_back({htonl(ip), htonl(netmask), ifa->ifa_name});
    }
  }
  freeifaddrs(ifap);
  return ifas_info;
}

std::string GetHostName() {
  char hostname[HOST_NAME_MAX];
  gethostname(hostname, sizeof(hostname));
  return std::string(hostname);
}

AuditDataBase::AuditDataBase() : kHostID{GetHostID(kHostIDFilename)} {
  if (kHostID == 0) {
    throw std::runtime_error("Error to get host id in AuditDataBase()");
  }
}

AuditDataBase::AuditDataBase(std::string_view url, std::string_view user,
                             std::string_view pass, std::string_view database)
    : DataBase{url, user, pass, database}, kHostID{GetHostID(kHostIDFilename)} {
  if (kHostID == 0) {
    throw std::runtime_error("Error to get host id in AuditDataBase()");
  }
}

void AuditDataBase::Sync() {
  AddHost();
  auto local_info{GetLocalUsersGroupsInfo()};
  DeleteUsers(local_info.users);
  DeleteGroups(local_info.groups);
  DeleteUsersGroups(local_info.users);
  auto db_info{GetDataBaseUsersGroupsInfo()};
  AddChangeUsers(local_info, db_info);
  AddChangeGroups(local_info, db_info);
  AddUsersGroups(local_info, db_info);
}

void AuditDataBase::AddHost() {
  const auto ifas_info{GetHostIPs()};
  const auto host_name{GetHostName()};
  std::ostringstream query{};
  query << "select id, name from audit.hosts where id = " << kHostID;
  auto result = ExecuteQuery(query.str());
  query.str("");
  if (result->rowsCount() < 1) {
    query << "insert into audit.hosts(id, name) values(" << kHostID << ",'"
          << host_name << "')";
    Execute(query.str());
    query.str("");
  } else {
    result->next();
    if (host_name != result->getString(2)) {
      query << "update audit.hosts set name = '" << host_name
            << "' where id = " << kHostID;
      Execute(query.str());
      query.str("");
    }
    query << "delete from audit.hosts_ips where host_id = " << kHostID;
    Execute(query.str());
    query.str("");
  }
  auto first{true};
  query << "insert into audit.hosts_ips(host_id, ip, netmask, ifa_name) values";
  for (const auto& ifa_info : ifas_info) {
    if (!first) {
      query << ',';
    }
    query << '(' << kHostID << ',' << ifa_info.ip << ',' << ifa_info.netmask
          << ",'" << ifa_info.ifa_name << "')";
    first = false;
  }
  Execute(query.str());
}

AuditDataBase::UsersGroupsInfo AuditDataBase::GetLocalUsersGroupsInfo() {
  UsersGroupsInfo local_users_info{};
  while (true) {
    const struct passwd* pw = getpwent();
    if (!pw) {
      break;
    }
    local_users_info.users[pw->pw_uid].name = pw->pw_name;
    int ngroups{0};
    getgrouplist(pw->pw_name, pw->pw_gid, nullptr, &ngroups);
    gid_t groups[ngroups];
    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);
    for (int i{0}; i < ngroups; ++i) {
      const struct group* gr = getgrgid(groups[i]);
      local_users_info.groups[groups[i]] = gr->gr_name;
      local_users_info.users[pw->pw_uid].gids.insert(groups[i]);
    }
  }
  endpwent();
  return local_users_info;
}

void AuditDataBase::DeleteUsers(const std::map<uid_t, UserInfo>& users) {
  std::ostringstream query{};
  query << "update audit.users set enabled = false where host_id = " << kHostID
        << " and (id < " << users.cbegin()->first;
  for (auto it = users.cbegin(); std::next(it) != users.cend(); ++it) {
    uid_t current{it->first}, next{std::next(it)->first};
    if ((next - current) > 1) {
      query << " or id > " << current << " and id < " << next;
    }
  }
  query << " or id > " << users.crbegin()->first << ')';
  Execute(query.str());
}

void AuditDataBase::DeleteGroups(const std::map<uid_t, std::string>& groups) {
  std::ostringstream query{};
  query << "update audit.groups set enabled = false where host_id = " << kHostID
        << " and (id < " << groups.cbegin()->first;
  for (auto it = groups.cbegin(); std::next(it) != groups.end(); ++it) {
    uid_t current{it->first}, next{std::next(it)->first};
    if ((next - current) > 1) {
      query << " or id > " << current << " and id < " << next;
    }
  }
  query << " or id > " << groups.crbegin()->first << ')';
  Execute(query.str());
}

void AuditDataBase::DeleteUsersGroups(const std::map<uid_t, UserInfo>& users) {
  /*
  Execute(
      "delete audit.users_groups from audit.users_groups inner join "
      "(audit.users, audit.groups) on  audit.users.id = "
      "audit.users_groups.user_id and audit.groups.id = "
      "audit.users_groups.group_id where audit.users.enabled = false  or "
      "audit.groups.enabled = false; ");
  */
  std::ostringstream query{};
  query << "delete from audit.users_groups where host_id = " << kHostID
        << " and (";
  auto deleted{false};
  auto first{true};
  for (const auto& user : users) {
    if (!first) {
      query << " or ";
    }
    first = false;
    query << "user_id = " << user.first << " and (group_id < "
          << *user.second.gids.cbegin();
    for (auto it_group = user.second.gids.cbegin();
         std::next(it_group) != user.second.gids.cend(); ++it_group) {
      deleted = true;
      gid_t current{*it_group}, next{*std::next(it_group)};
      if ((next - current) > 1) {
        query << " or group_id > " << current << " and group_id < " << next;
      }
    }
    query << " or group_id > " << *user.second.gids.crbegin() << ')';
  }
  query << ')';
  if (deleted) {
    Execute(query.str());
  }
}

AuditDataBase::DataBaseUsersGroupsInfo
AuditDataBase::GetDataBaseUsersGroupsInfo() {
  DataBaseUsersGroupsInfo db_info{};
  std::ostringstream query{};
  query << "select id, name, enabled from audit.users where host_id = "
        << kHostID;
  auto result = ExecuteQuery(query.str());
  while (result->next()) {
    uid_t uid{result->getUInt(1)};
    db_info.users[uid].name = result->getString(2);
    if (result->getBoolean(3)) {
      db_info.users_enabled.insert(uid);
    }
  }
  query.str("");

  query << "select id, name, enabled from audit.groups where host_id = "
        << kHostID;
  result = std::unique_ptr<sql::ResultSet>{ExecuteQuery(query.str())};
  while (result->next()) {
    gid_t gid{result->getUInt(1)};
    db_info.groups[gid] = result->getString(2);
    if (result->getBoolean(3)) {
      db_info.groups_enabled.insert(gid);
    }
  }
  query.str("");

  query << "select user_id, group_id from audit.users_groups where host_id = "
        << kHostID;
  result = std::unique_ptr<sql::ResultSet>{ExecuteQuery(query.str())};
  while (result->next()) {
    uid_t uid{result->getUInt(1)};
    gid_t gid{result->getUInt(2)};
    db_info.users[uid].gids.insert(gid);
  }
  return db_info;
}

void AuditDataBase::AddChangeUsers(const UsersGroupsInfo& local_info,
                                   const DataBaseUsersGroupsInfo& db_info) {
  std::ostringstream query{};
  query << "insert into audit.users(host_id, id, name) values";
  auto added{false};
  for (const auto& local_user : local_info.users) {
    auto ptr{db_info.users.find(local_user.first)};
    if (ptr == db_info.users.cend()) {
      if (added) {
        query << ',';
      }
      query << '(' << kHostID << ',' << local_user.first << ",'"
            << local_user.second.name << "')";
      added = true;
      continue;
    }
    std::ostringstream query_change{};
    query_change << "update audit.users ";
    auto names_equal{ptr->second.name == local_user.second.name};
    auto disabled{db_info.users_enabled.find(local_user.first) ==
                  db_info.users_enabled.cend()};
    if (!names_equal) {
      query_change << "set name = '" << local_user.second.name << '\'';
      if (disabled) {
        query_change << ",enabled = true";
      }
    } else if (disabled) {
      query_change << "set enabled = true";
    } else {
      continue;
    }
    query_change << " where host_id = " << kHostID
                 << " and id = " << local_user.first;
    Execute(query_change.str());
  }
  if (added) {
    Execute(query.str());
  }
}

void AuditDataBase::AddChangeGroups(const UsersGroupsInfo& local_info,
                                    const DataBaseUsersGroupsInfo& db_info) {
  std::ostringstream query{};
  query << "insert into audit.groups(host_id, id, name) values";
  auto added{false};
  for (const auto& local_group : local_info.groups) {
    auto ptr{db_info.groups.find(local_group.first)};
    if (ptr == db_info.groups.cend()) {
      if (added) {
        query << ',';
      }
      query << '(' << kHostID << ',' << local_group.first << ",'"
            << local_group.second << "')";
      added = true;
      continue;
    }
    std::ostringstream query_change{};
    query_change << "update audit.groups ";
    auto names_equal{ptr->second == local_group.second};
    auto disabled{db_info.groups_enabled.find(local_group.first) ==
                  db_info.groups_enabled.cend()};
    if (!names_equal) {
      query_change << "set name = '" << local_group.second << '\'';
      if (disabled) {
        query_change << ",enabled = true";
      }
    } else if (disabled) {
      query_change << "set enabled = true";
    } else {
      continue;
    }
    query_change << " where host_id = " << kHostID
                 << " and id = " << local_group.first;
    Execute(query_change.str());
  }
  if (added) {
    Execute(query.str());
  }
}

void AuditDataBase::AddUsersGroups(const UsersGroupsInfo& local_info,
                                   const DataBaseUsersGroupsInfo& db_info) {
  std::ostringstream query{};
  query << "insert into audit.users_groups(host_id, user_id, group_id) values";
  auto added{false};
  for (const auto& local_user : local_info.users) {
    const auto db_user_ptr{db_info.users.find(local_user.first)};
    for (const auto& local_group : local_user.second.gids) {
      if (db_user_ptr != db_info.users.cend() &&
          db_user_ptr->second.gids.find(local_group) !=
              db_user_ptr->second.gids.cend()) {
        continue;
      }
      if (added) {
        query << ',';
      }
      query << '(' << kHostID << ',' << local_user.first << ',' << local_group
            << ')';
      added = true;
      continue;
    }
  }
  if (added) {
    Execute(query.str());
  }
}

std::uint32_t AuditDataBase::HostID() { return kHostID; }

void AuditDataBase::AddSetuid(const struct setuid_data_t* data) {
  auto prstmt{
      PreparedStatement("insert into audit.setuid values(?,?,?,?,?,?,?)")};
  prstmt->setUInt64(1, data->time_nsec);
  prstmt->setUInt(2, kHostID);
  prstmt->setUInt(3, data->uid);
  prstmt->setUInt(4, data->setuid);
  prstmt->setInt(5, data->pid);
  prstmt->setString(6, data->comm);
  prstmt->setInt(7, data->ret);
}

void AuditDataBase::AddExecve(const struct execve_data_t* data) {
  auto prstmt{
      PreparedStatement("insert into audit.execve values(?,?,?,?,?,?,?,?)")};
  prstmt->setUInt64(1, data->time_nsec);
  prstmt->setUInt(2, kHostID);
  prstmt->setUInt(3, data->uid);
  prstmt->setInt(4, data->pid);
  prstmt->setInt(5, data->ppid);
  prstmt->setString(6, data->pwd);
  prstmt->setString(7, data->comm);
  if (data->argv[0]) {
    prstmt->setString(8, data->argv);
  } else {
    prstmt->setNull(8, 0);
  }
  prstmt->execute();
}

void AuditDataBase::AddExit(const struct exit_data_t* data) {
  auto prstmt{PreparedStatement("insert into audit.exit values(?,?,?,?,?,?)")};
  prstmt->setUInt64(1, data->time_nsec);
  prstmt->setUInt(2, kHostID);
  prstmt->setUInt(3, data->uid);
  prstmt->setInt(4, data->pid);
  prstmt->setString(5, data->comm);
  prstmt->setInt(6, data->code);
  prstmt->execute();
}

void AuditDataBase::AddFile(const std::string& operation,
                            const struct file_data_t* data,
                            const char* filename, const char* argv) {
  auto prstmt{
      PreparedStatement("insert into audit.files values(?,?,?,?,?,?,?,?,?)")};
  prstmt->setUInt64(1, data->time_nsec);
  prstmt->setString(2, operation);
  prstmt->setUInt(3, kHostID);
  prstmt->setUInt(4, data->uid);
  prstmt->setInt(5, data->pid);
  prstmt->setString(6, data->comm);
  prstmt->setString(7, filename);
  if (argv) {
    prstmt->setString(8, argv);
  } else {
    prstmt->setNull(8, 0);
  }
  prstmt->setInt(9, data->ret);
  prstmt->execute();
}

void AuditDataBase::AddTcp(const std::string& operation,
                           const struct tcp_data_t* data,
                           const std::string& source_ip,
                           std::uint16_t source_port,
                           const std::string& dest_ip,
                           std::uint16_t dest_port) {
  std::ostringstream query{};
  query << "insert into audit.tcp values(" << data->time_nsec << ",'"
        << operation << "'," << kHostID << ',' << data->uid << ',' << data->pid
        << ",'" << data->comm << "'," << source_ip << ',' << source_port << ','
        << dest_ip << ',' << dest_port << ')';
  Execute(query.str());
}

}  // namespace audit
