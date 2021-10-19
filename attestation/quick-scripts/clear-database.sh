#/bin/sh

sql=$(cat ../ras/dao/clearTable.sql)
sudo su - postgres <<EOF
psql -d kunpengsecl -U postgres -c "$sql";
EOF
