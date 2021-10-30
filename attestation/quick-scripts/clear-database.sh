#/bin/sh

sqldropfile=../ras/dao/dropTable.sql
sqlcreate=$(cat ../ras/dao/createTable.sql)

while read line
do
	echo $line
	sudo su - postgres -c "psql -d kunpengsecl -U postgres -c '$line'"
done < $sqldropfile

sudo su - postgres -c "psql -d kunpengsecl -U postgres -c '$sqlcreate'"
