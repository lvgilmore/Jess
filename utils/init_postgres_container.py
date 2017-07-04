import psycopg2
from os import environ


connection_string = "dbname='{dbname}' host='{dbhost}' user='{dbuser}' password='{dbpass}'".format(
    dbname=environ.get('PG_DB', 'postgres'), dbhost=environ.get('DB_HOST', 'jess-postgres'),
    dbuser=environ.get('PG_SUPERUSER', 'postgres'), dbpass=environ.get('PG_PASSWORD', 'ssshimbatman')
)
connection = psycopg2.connect(connection_string)
connection.set_isolation_level(0)
cur = connection.cursor()
cur.execute("CREATE USER {user} WITH NOSUPERUSER NOCREATEDB LOGIN PASSWORD '{pswd}' ;".format(
    user=environ.get('DB_USER', 'psyco'), pswd=environ('DB_PASS', 'shit')
))
cur.execute("CREATE DATABASE {db} WITH OWNER = '{user}' ;".format(
    user=environ.get('DB_USER', 'psyco'), db=environ.get('DB_NAME', 'grand_policy')
))
connection.close()


connection_string = "dbname='{dbname}' host='{dbhost}' user='{dbuser}' password='{dbpass}'".format(
    dbname=environ.get('DB_NAME', 'grand_policy'), dbhost=environ.get('DB_HOST', 'jess-postgres'),
    dbuser=environ.get('DB_USER', 'psyco'), dbpass=environ.get('DB_PASS', 'shit')
)
connection = psycopg2.connect(connection_string)
connection.set_isolation_level(0)
cur = connection.cursor()
cur.execute("firewallrules (source cidr, destination cidr, protocol varchar(50), action int, "
            "primary key (source, destination, protocol)) ; ")
connection.close()
