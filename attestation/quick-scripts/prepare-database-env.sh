#/bin/sh
osv=`grep "\<NAME=" /etc/os-release | awk -F '[" ]' '{print $2}'`
# install deps
ubuntu_deps="postgresql"
openeuler_deps="postgresql-server"

case $osv in
    Ubuntu)
        sudo apt-get install $ubuntu_deps
        ;;
    openEuler|CentOS)
        sudo dnf -y --allowerasing install $openeuler_deps
        sudo su - postgres <<EOF
initdb --pgdata="/var/lib/pgsql/data" --auth=ident
sed -i "s/ ident/ md5/g" ~/data/pg_hba.conf
pg_ctl -D /var/lib/pgsql/data start
EOF
        ;;
    *)
        echo $osv is not supported yet
        exit 1
        ;;
esac

sql=$(cat ./createTable.sql)
sudo su - postgres <<EOF
psql -U postgres -c "alter user postgres with password 'postgres';";
psql -U postgres -c "create database kunpengsecl owner postgres;";
psql -U postgres -c "grant all privileges on database kunpengsecl to postgres;";
psql -d kunpengsecl -U postgres -c "$sql";
EOF

