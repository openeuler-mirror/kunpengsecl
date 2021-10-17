#/bin/sh

sql=$(cat ../ras/dao/createTable.sql)
sudo dnf install postgresql-server -y
sudo postgresql-setup --initdb
sudo systemctl enable postgresql.service
sudo systemctl start postgresql.service
sudo su - postgres <<EOF
psql -U postgres -c "create database kunpengsecl owner postgres;";
psql -U postgres -c "grant all privileges on database kunpengsecl to postgres;";
psql -d kunpengsecl -U postgres -c "$sql";
EOF