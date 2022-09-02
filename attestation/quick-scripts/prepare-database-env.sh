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
        sudo dnf -y install openldap-devel
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

DB_USER=${DB_USER:-postgres}
DB_PASS=${DB_PASS:-postgres}

if (($# == 2)) 
then
    DB_USER=$1
    DB_PASS=$2
fi

sql=$(cat ./createTable.sql)
sudo su - postgres <<EOF
psql -U $DB_USER -c "alter user $DB_USER with password '$DB_PASS';";
psql -U $DB_USER -c "create database kunpengsecl owner $DB_USER;";
psql -U $DB_USER -c "grant all privileges on database kunpengsecl to $DB_USER;";
psql -d kunpengsecl -U $DB_USER -c "$sql";
EOF

