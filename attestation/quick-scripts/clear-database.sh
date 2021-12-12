#/bin/sh

sqldropfile=./dropTable.sql
sqlcreate=$(cat ./createTable.sql)

while read line
do
	echo $line
	sudo su - postgres -c "psql -d kunpengsecl -U postgres -c '$line'"
done < $sqldropfile

sudo su - postgres -c "psql -d kunpengsecl -U postgres -c '$sqlcreate'"
