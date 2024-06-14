create table if not exists hosts(
  id bigint,
  name varchar(64),
  primary key(id));

create table if not exists hosts_ips(
  host_id bigint,
  ip inet,
  ifa_name varchar(32),
  foreign key(host_id) references hosts(id));

create table if not exists users(
  host_id bigint,
  id int,
  name varchar(32),
  enabled boolean default true,
  primary key(host_id, id),
  foreign key(host_id) references hosts(id));

create table if not exists groups(
  host_id bigint,
  id int,
  name varchar(32),
  enabled boolean default true,
  primary key(host_id, id),
  foreign key(host_id) references hosts(id));

create table if not exists users_groups(
  host_id bigint,
  user_id int,
  group_id int,
  primary key(host_id, user_id, group_id),
  foreign key(host_id, user_id) references users(host_id, id),
  foreign key(host_id, group_id) references groups(host_id, id));

create table if not exists setuid(
  time_nsec bigint,
  host_id bigint,
  user_id int,
  set_user_id int,
  pid int,
  command varchar(16),
  ret int,
  foreign key(host_id) references hosts(id));
create index setuid_index on setuid(user_id, pid);

create table if not exists execve(
  time_nsec bigint,
  host_id bigint,
  user_id int,
  pid int,
  ppid int,
  directory varchar(4096),
  command varchar(16),
  argv varchar(1024),
  foreign key(host_id) references hosts(id));
create index execve_index on execve(user_id, pid, ppid);

create table if not exists exit(
  time_nsec bigint,
  host_id bigint,
  user_id int,
  pid int,
  command varchar(16),
  exit_code int,
  foreign key(host_id) references hosts(id));
create index exit_index on exit(user_id, pid);

create type file_operation as enum('unlink', 'openat', 'mkdir', 'rename', 'chmod', 'chown');
create table if not exists files(
  time_nsec bigint,
  operation file_operation,
  host_id bigint,
  user_id int,
  pid int,
  command varchar(16),
  filename varchar(4096),
  argv varchar(4096),
  ret int,
  foreign key(host_id) references hosts(id));
create index files_index on files(user_id, pid);

create type tcp_operation as enum('connect', 'accept');
create table if not exists tcp(
  time_nsec bigint,
  operation tcp_operation,
  host_id bigint,
  user_id int,
  pid int,
  command varchar(16),
  source_ip inet,
  source_port int,
  dest_ip inet,
  dest_port int,
  foreign key(host_id) references hosts(id));
create index tcp_index on tcp(user_id, pid);

create role client;
grant select, insert, update(name) on hosts to client;
grant select, insert, delete on hosts_ips to client;
grant select, insert, update(name, enabled) on users to client;
grant select, insert, update(name, enabled) on groups to client;
grant select, insert, delete on users_groups to client;
grant insert on setuid, execve, exit, files, tcp to client;
create user client_user password 'client';
grant client to client_user;

create or replace function delete_users()
  returns void
  language sql
  begin atomic
  delete from users_groups a using users b
    where b.id = a.user_id
    and b.enabled = false;
  end;

create or replace function delete_users_trigger()
  returns trigger as $$
  begin
    perform delete_users();
    return new;
  end;
  $$
  language plpgsql;

create or replace function delete_groups()
  returns void
  language sql
  begin atomic
  delete from users_groups a using groups b
    where b.id = a.group_id
    and b.enabled = false;
  end;

create or replace function delete_groups_trigger()
  returns trigger as $$
  begin
    perform delete_groups();
    return new;
  end;
  $$
  language plpgsql;

create trigger user_disable after update of enabled on users
  for each statement
  execute function delete_users_trigger();

create trigger group_disable after update of enabled on groups
  for each statement
  execute function delete_groups_trigger();

