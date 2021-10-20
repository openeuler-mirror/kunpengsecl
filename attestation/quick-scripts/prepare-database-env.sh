#/bin/sh

sql=$(cat ../ras/dao/createTable.sql)
sudo dnf install postgresql-server -y
sudo su - postgres <<EOF
initdb --pgdata="/var/lib/pgsql/data" --auth=ident
sed -i "s/ ident/ md5/g" ~/data/pg_hba.conf
pg_ctl -D /var/lib/pgsql/data start
psql -U postgres -c "alter user postgres with password 'postgres';";
psql -U postgres -c "create database kunpengsecl owner postgres;";
psql -U postgres -c "grant all privileges on database kunpengsecl to postgres;";
psql -d kunpengsecl -U postgres -c "$sql";
EOF
