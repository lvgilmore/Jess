#!/usr/bin/env bash

yum install -y postgresql95 postgresql95-server 2> /dev/null
if sudo systemctl start postgresql-9.5.service
then
  echo
else
  sudo /usr/pgsql-9.5/bin/postgresql95-setup initdb
  sudo systemctl restart postgresql-9.5.service
fi

#install db itself
sudo -u postgres dropdb --if-exists grand_policy
sudo -u postgres dropuser --if-exists psyco
# TODO: find a way to create user without interactively entering password
sudo -u postgres createuser --pwprompt --login --no-superuser --no-createrole --createdb psyco
sudo -u postgres createdb --owner psyco grand_policy
sudo -u postgres createdb --owner=psyco policy_optimizer_test

#allow psyco to connect using password
sed -i '/host\s*all\s*all\s*127.0.0.1/i host\tgrand_policy\t\tpsyco\t127.0.0.1\/32\t\tmd5' /var/lib/pgsql/9.5/data/pg_hba.conf
sed -i '/host\s*all\s*all\s*::1\/128/i host\tgrand_policy\t\tpsyco\t::1/128\t\tmd5' /var/lib/pgsql/9.5/data/pg_hba.conf
sed -i '/host\s*all\s*all\s*::1\/128/i host\tpolicy_optimizer_test\t\tpsyco\t::1/128\t\tmd5' /var/lib/pgsql/9.5/data/pg_hba.conf
sudo -u postgres /usr/pgsql-9.5/bin/pg_ctl reload

psql --dbname=grand_policy --username=psyco --host=localhost --password --command="create table firewallrules \
(source cidr, destination cidr, protocol varchar(50), action int, primary key(source, destination, protocol)) ; "
