insert into groups(group_name) values ('Users');
insert into groups(group_name) values ('Administrators');

insert into group_authorities(group_id, authority) select id,'ROLE_USER' from groups where group_name='Users'; 
insert into group_authorities(group_id, authority) select id,'ROLE_USER' from groups where group_name='Administrators'; 
insert into group_authorities(group_id, authority) select id,'ROLE_ADMIN' from groups where group_name='Administrators'; 

-- username: admin
-- password: admin
insert into users(username, password, enabled, salt) values 
  ('admin','5d7d0dd6d9e8b1688474765898adf7d3abd06385b6030e5109a567ee09880eb1',true,'1304167344334');

--insert into authorities(username,authority) values ('admin','ROLE_USER');
--insert into authorities(username,authority) values ('admin','ROLE_ADMIN');

insert into group_members(group_id, username) select id,'admin' from groups where group_name='Administrators';

commit;
