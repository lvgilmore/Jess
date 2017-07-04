# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import psycopg2

from Jess import configs
from Jess.Policy.firewall_rule import FirewallRule
from Jess.Policy.PolicyLoader.grand_policy_loader import GrandPolicyLoader


# TODO: copy todos from gpl
class PostgresGPL(GrandPolicyLoader):
    @classmethod
    def identifiers(cls):
        return ['postgres', 'pgpl', 'posgtres-gpl']

    def __init__(self, *args, **kwargs):
        super(PostgresGPL, self).__init__(*args, **kwargs)
        dbname = kwargs.get('dbname', configs.dbname)
        host = kwargs.get('dbhost', configs.dbhost)
        user = kwargs.get('dbuser', configs.dbuser)
        password = kwargs.get('dbpass', configs.dbpass)
        self.connection_string ="dbname='{dbname}' host='{dbhost}' user='{dbuser}' password='{dbpass}'".format(
            dbname=dbname, dbhost=host, dbuser=user, dbpass=password
        )
        self._insert_rules()

    def _insert_rules(self):
        connection = psycopg2.connect(self.connection_string)
        cursor = connection.cursor()
        for rule in self.rules:
            try:
                cursor.execute("insert into firewallrules(source, destination, protocol, action)"
                               "values ({src}, {dst}, {prtcl}, {act}) ;".format(
                                src=rule.source, dst=rule.destination, prtcl=rule.protocol, act=rule.action
                                ))
            except psycopg2.IntegrityError:
                cursor.execute("update table firewallrules set action='{act}' "
                               "where source='{src}' and destination='{dst} and protocol={prtcl} ;".format(
                                src=rule.source, dst=rule.destination, prtcl=rule.protocol, act=rule.action
                                ))
            connection.commit()
        connection.close()

    def load(self):
        connection = psycopg2.connect(self.connection_string)
        cursor = connection.cursor()
        cursor.execute("select source, destination, protocol, action from firewallrules ;")
        self.rules = []
        for row in cursor.fetchall():
            self.rules.append(FirewallRule(source=row[0], destination=row[1], protocol=row[2], action=row[3]))
        connection.close()

    def get_rules(self, source=None, destination=None, protocol=None, action=None):
        wherestring = "where "
        wherestring += "source >>= cidr('{}') and ".format(source) if source is not None else ""
        wherestring += "destination >>= cidr('{}') and ".format(destination) if destination is not None else ""
        wherestring += "protocol ~ '(^| ){}( |$)' and ".format(protocol) if protocol is not None else ""
        wherestring += "action = {} and ".format(action) if action is not None else ""
        wherestring = wherestring.strip("and ")
        connection = psycopg2.connect(self.connection_string)
        cursor = connection.cursor()
        wherestring = " {} ;".format(wherestring) if wherestring != "where" else " ;"
        cursor.execute("select source, destination, protocol, action from firewallrules {}".format(wherestring))
        rules = []
        for row in cursor.fetchall():
            rules.append(FirewallRule(source=row[0], destination=row[1], protocol=row[2], action=row[3]))
        connection.close()
        return rules

    def update_rule(self, existing_rule, new_rule):
        connection = psycopg2.connect(self.connection_string)
        cursor = connection.cursor()
        cursor.execute("update firewallrules "
                       "set source = cidr('{nsource}'), destination = cidr('{ndestination}'), "
                       "protocol = '{nprotocol}', action = {naction} "
                       "where source = cidr('{osource}') and destination = cidr('{odestination}') and "
                       "protocol = '{oprotocol}' and action = {oaction} ;"
                       "".format(nsource=new_rule.source, ndestination=new_rule.destination,
                                 nprotocol=new_rule.protocol, naction=new_rule.action,
                                 osource=existing_rule.source, odestination=existing_rule.destination,
                                 oprotocol=existing_rule.protocol, oaction=existing_rule.action,))
        connection.commit()
        connection.close()
        return True

    def add_rule(self, rule):
        connection = psycopg2.connect(self.connection_string)
        cursor = connection.cursor()
        cursor.execute("insert into firewallrules(source, destination, protocol, action) "
                       "values (cidr('{src}'), cidr('{dst}'), '{prtcl}', {act}) ;".format(
                            src=rule.source, dst=rule.destination, prtcl=rule.protocol, act=rule.action))
        connection.commit()
        connection.close()
        return True
