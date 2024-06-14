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
    return static_cast<int>(host_id);
  } else {
    std::uint32_t host_id;
    file_in >> host_id;
    file_in.close();
    return host_id;
  }
}

struct HostIP {
  std::string ip;
  int netmask;
  std::string ifa_name;
};

int NumberOfSetBits(in_addr_t i) {
  i = i - ((i >> 1) & 0x55555555);
  i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
  i = (i + (i >> 4)) & 0x0F0F0F0F;
  i *= 0x01010101;
  return static_cast<int>(i >> 24);
}

std::vector<HostIP> GetHostIPs() {
  std::vector<HostIP> ifas_info{};
  struct ifaddrs *ifap, *ifa;
  getifaddrs(&ifap);
  constexpr std::uint32_t localhost{0x7F};
  constexpr std::string::size_type size{16};
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_netmask && ifa->ifa_name &&
        ifa->ifa_addr->sa_family == AF_INET) {
      auto sockaddr{reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)};
      auto ip{sockaddr->sin_addr};
      if ((ip.s_addr & localhost) == localhost) continue;
      sockaddr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
      auto netmask{NumberOfSetBits(sockaddr->sin_addr.s_addr)};
      HostIP info{std::string(size, '\0'), netmask, ifa->ifa_name};
      inet_ntop(AF_INET, &ip, info.ip.data(), size);
      ifas_info.push_back(info);
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
  Commit();
}

void AuditDataBase::AddHost() {
  const auto ifas_info{GetHostIPs()};
  const auto host_name{GetHostName()};
  std::ostringstream query{};
  query << "select id, name from hosts where id = " << kHostID;
  auto result{ExecuteQuery(query.str())};
  query.str("");
  if (result.size() < 1) {
    query << "insert into hosts values(" << kHostID << ",'" << host_name
          << "')";
    Execute(query.str());
    query.str("");
  } else {
    if (host_name != result[0][1].view()) {
      query << "update hosts set name = '" << host_name
            << "' where id = " << kHostID;
      Execute(query.str());
      query.str("");
    }
    query << "delete from hosts_ips where host_id = " << kHostID;
    Execute(query.str());
    query.str("");
  }
  auto first{true};
  query << "insert into hosts_ips values";
  for (const auto& ifa_info : ifas_info) {
    if (!first) {
      query << ',';
    }
    query << '(' << kHostID << ",'" << ifa_info.ip.c_str() << '/'
          << ifa_info.netmask << "','" << ifa_info.ifa_name << "')";
    first = false;
  }
  Execute(query.str());
}

AuditDataBase::UsersGroupsInfo AuditDataBase::GetLocalUsersGroupsInfo() {
  UsersGroupsInfo local_users_info{};
  while (true) {
    const struct passwd* pw{getpwent()};
    if (!pw) {
      break;
    }
    local_users_info.users[pw->pw_uid].name = pw->pw_name;
    using SizeType = std::vector<gid_t>::size_type;
    SizeType ngroups{0};
    auto int_ptr{reinterpret_cast<int*>(&ngroups)};
    getgrouplist(pw->pw_name, pw->pw_gid, nullptr, int_ptr);
    std::vector<gid_t> groups(ngroups);
    getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), int_ptr);
    for (SizeType i{0}; i < ngroups; ++i) {
      const struct group* gr{getgrgid(groups[i])};
      local_users_info.groups[groups[i]] = gr->gr_name;
      local_users_info.users[pw->pw_uid].gids.insert(groups[i]);
    }
  }
  endpwent();
  return local_users_info;
}

void AuditDataBase::DeleteUsers(const std::map<uid_t, UserInfo>& users) {
  std::ostringstream query{};
  query << "update users set enabled = false where host_id = " << kHostID
        << " and (id < " << users.cbegin()->first;
  for (auto it{users.cbegin()}; std::next(it) != users.cend(); ++it) {
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
  query << "update groups set enabled = false where host_id = " << kHostID
        << " and (id < " << groups.cbegin()->first;
  for (auto it{groups.cbegin()}; std::next(it) != groups.end(); ++it) {
    uid_t current{it->first}, next{std::next(it)->first};
    if ((next - current) > 1) {
      query << " or id > " << current << " and id < " << next;
    }
  }
  query << " or id > " << groups.crbegin()->first << ')';
  Execute(query.str());
}

void AuditDataBase::DeleteUsersGroups(const std::map<uid_t, UserInfo>& users) {
  std::ostringstream query{};
  query << "delete from users_groups where host_id = " << kHostID << " and (";
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
  query << "select id, name, enabled from users where host_id = " << kHostID;
  auto result{ExecuteQuery(query.str())};
  for (const auto& row : result) {
    auto uid{row[0].as<uid_t>()};
    db_info.users[uid].name = row[1].view();
    if (row[2].as<bool>()) {
      db_info.users_enabled.insert(uid);
    }
  }
  query.str("");

  query << "select id, name, enabled from groups where host_id = " << kHostID;
  result = ExecuteQuery(query.str());
  for (const auto& row : result) {
    gid_t gid{row[0].as<gid_t>()};
    db_info.groups[gid] = row[1].view();
    if (row[2].as<bool>()) {
      db_info.groups_enabled.insert(gid);
    }
  }
  query.str("");

  query << "select user_id, group_id from users_groups where host_id = "
        << kHostID;
  result = ExecuteQuery(query.str());
  for (const auto& row : result) {
    uid_t uid{row[0].as<uid_t>()};
    gid_t gid{row[1].as<gid_t>()};
    db_info.users[uid].gids.insert(gid);
  }
  return db_info;
}

void AuditDataBase::AddChangeUsers(const UsersGroupsInfo& local_info,
                                   const DataBaseUsersGroupsInfo& db_info) {
  std::ostringstream query{};
  query << "insert into users values";
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
    query_change << "update users ";
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
  query << "insert into groups(host_id, id, name) values";
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
    query_change << "update groups ";
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
  query << "insert into users_groups values";
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

std::int32_t AuditDataBase::HostID() { return kHostID; }

void AuditDataBase::AddSetuid(const struct setuid_data_t* data) {
  ExecParams0("insert into setuid values($1,$2,$3,$4,$5,$6,$7)",
              data->time_nsec, kHostID, data->uid, data->setuid, data->pid,
              data->comm, data->ret);
  Commit();
}

void AuditDataBase::AddExecve(const struct execve_data_t* data) {
  ExecParams0("insert into execve values($1,$2,$3,$4,$5,$6,$7,$8)",
              data->time_nsec, kHostID, data->uid, data->pid, data->ppid,
              data->pwd, data->comm, data->argv);
  Commit();
}

void AuditDataBase::AddExit(const struct exit_data_t* data) {
  ExecParams0("insert into exit values($1,$2,$3,$4,$5,$6)", data->time_nsec,
              kHostID, data->uid, data->pid, data->comm, data->code);
  Commit();
}

void AuditDataBase::AddFile(const std::string& operation,
                            const struct file_data_t* data,
                            const char* filename, const char* argv) {
  ExecParams0("insert into files values($1,$2,$3,$4,$5,$6,$7,$8,$9)",
              data->time_nsec, operation, kHostID, data->uid, data->pid,
              data->comm, filename, argv, data->ret);
  Commit();
}

void AuditDataBase::AddTcp(std::string_view operation,
                           const struct tcp_data_t* data,
                           std::string_view source_ip,
                           std::uint16_t source_port, std::string_view dest_ip,
                           std::uint16_t dest_port) {
  ExecParams0("insert into tcp values($1,$2,$3,$4,$5,$6,$7,$8,$9, $10)",
              data->time_nsec, operation, kHostID, data->uid, data->pid,
              data->comm, source_ip, source_port, dest_ip, dest_port);
  Commit();
}

}  // namespace audit
