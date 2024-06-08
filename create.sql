create database if not exists audit;
use audit;

create table if not exists audit.hosts(
  id int unsigned,
  name varchar(64),
  primary key(id));

create table if not exists audit.hosts_ips(
  host_id int unsigned,
  ip int unsigned,
  netmask int unsigned,
  ifa_name varchar(32),
  foreign key(host_id) references audit.hosts(id));

create table if not exists audit.users(
  host_id int unsigned,
  id int unsigned,
  name varchar(32),
  enabled bit(1) default true,
  primary key(host_id, id),
  foreign key(host_id) references audit.hosts(id));

create table if not exists audit.groups(
  host_id int unsigned,
  id int unsigned,
  name varchar(32),
  enabled bit(1) default true,
  primary key(host_id, id),
  foreign key(host_id) references audit.hosts(id));

create table if not exists audit.users_groups(
  host_id int unsigned,
  user_id int unsigned,
  group_id int unsigned,
  primary key(host_id, user_id, group_id),
  foreign key(host_id, user_id) references audit.users(host_id, id),
  foreign key(host_id, group_id) references audit.groups(host_id, id));

create view audit.hosts_ips_view as
select host_id, inet_ntoa(ip), inet_ntoa(netmask), ifa_name from hosts_ips;

create view audit.users_groups_view as
select audit.users_groups.host_id, audit.users_groups.user_id,
       audit.users_groups.group_id , audit.users.enabled as user_enabled,
       audit.groups.enabled as group_enabled
  from audit.users_groups inner join(audit.users, audit.groups)
                          on  audit.users_groups.user_id = audit.users.id
                          and audit.users_groups.group_id = audit.groups.id;

create table if not exists audit.execve(
  time_nsec bigint unsigned,
  host_id int unsigned,
  user_id int unsigned,
  pid int,
  ppid int,
  directory varchar(256),
  command varchar(16),
  argv varchar(1024),
  foreign key(host_id) references audit.hosts(id),
  index (user_id));

create table if not exists audit.exit(
  time_nsec bigint unsigned,
  host_id int unsigned,
  user_id int unsigned,
  pid int,
  command varchar(16),
  exit_code int,
  foreign key(host_id) references audit.hosts(id),
  index(user_id));

create table if not exists audit.setuid(
  time_nsec bigint unsigned,
  host_id int unsigned,
  user_id int unsigned,
  set_user_id int unsigned,
  pid int,
  command varchar(16),
  ret int,
  foreign key(host_id) references audit.hosts(id),
  index(user_id));

create table if not exists audit.files(
  time_nsec bigint unsigned,
  operation enum('unlink', 'openat', 'mkdir', 'rename', 'chmod', 'chown'),
  host_id int unsigned,
  user_id int unsigned,
  pid int,
  command varchar(16),
  filename varchar(4096),
  argv varchar(4096),
  ret int,
  foreign key(host_id) references audit.hosts(id),
  index(user_id));

create table if not exists audit.tcp(
  time_nsec bigint unsigned,
  operation enum('connect', 'accept'),
  host_id int unsigned,
  user_id int unsigned,
  pid int,
  command varchar(16),
  source_ip VARBINARY(16),
  source_port smallint unsigned,
  dest_ip VARBINARY(16),
  dest_port smallint unsigned,
  foreign key(host_id) references audit.hosts(id),
  index(user_id));

create view audit.tcp_view as
select from_unixtime(time_nsec/1000000000), operation, host_id, user_id, pid, command,
       inet6_ntoa(source_ip), source_port, inet6_ntoa(dest_ip), dest_port
  from audit.tcp;

create role 'client';
grant select, insert, update(name) on audit.hosts to 'client';
grant select, insert, delete on audit.hosts_ips to 'client';
grant select, insert, update(name, enabled) on audit.users to 'client';
grant select, insert, update(name, enabled) on audit.groups to 'client';
grant select, insert, delete on audit.users_groups to 'client';
grant insert on audit.setuid to 'client';
grant insert on audit.execve to 'client';
grant insert on audit.exit to 'client';
grant insert on audit.files to 'client';
grant insert on audit.tcp to 'client';
create user 'client_user' identified by 'client';
grant 'client' to 'client_user';
set default role all to 'client_user';

create trigger audit.user_disable after update on audit.users
  for each row
    delete audit.users_groups
      from audit.users_groups inner join audit.users
                              on audit.users.id = audit.users_groups.user_id
                              where audit.users.enabled = false;

create trigger audit.group_disable after update on audit.groups
  for each row
    delete audit.users_groups
      from audit.users_groups inner join audit.groups
                              on audit.groups.id = audit.users_groups.group_id
                              where audit.groups.enabled = false;
