import psycopg2

from ipaddr import IPNetwork
from unittest import TestCase
from Jess.Policy.firewall_rule import FirewallRule, FWACTION
from Jess.Policy.PolicyLoader.grand_policy_loader import GrandPolicyLoader
from Jess.Policy.PolicyLoader.posgres_grand_policy_loader import PostgresGPL
from Jess.Policy.policy_optimizer import PolicyOptimizer


class TestsPolicyOptimizer(TestCase):
    def test_basic_aggregation(self):
        gpl = GrandPolicyLoader(
            rules=[FirewallRule(source='1.1.1.0/32', destination='1.1.1.4/32', protocol='tcp/80', action=FWACTION.ACCEPT)]
        )

        optimizer = PolicyOptimizer(gpl=gpl)
        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='tcp/80', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.rules[0].source, IPNetwork('1.1.1.0/31'))

        optimizer.add_rule(FirewallRule(source='1.1.1.0/31', destination='1.1.1.5/32',
                                        protocol='tcp/80', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.rules[0].destination, IPNetwork('1.1.1.4/31'))

        optimizer.add_rule(FirewallRule(source='1.1.1.0/31', destination='1.1.1.4/31',
                                        protocol='tcp/443', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.rules[0].protocol, "tcp/80 tcp/443")

        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='tcp/443', action=FWACTION.ACCEPT))
        self.assertEqual(len(gpl.rules), 1)

        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='udp/443', action=FWACTION.ACCEPT))
        self.assertEqual(len(gpl.rules), 2)


class TestPolicyOptimizerPostgres(TestCase):
    @classmethod
    def setUpClass(cls):
        # create database test
        pass

    @classmethod
    def tearDownClass(cls):
        # delete database test
        pass

    def setUp(self):
        connection = psycopg2.connect("dbname='policy_optimizer_test' host='localhost' user='psyco' password='shit'")
        connection.set_isolation_level(0)
        cur = connection.cursor()
        cur.execute("create table firewallrules (source cidr, destination cidr, protocol varchar(50), action int, "
                    "primary key (source, destination, protocol)) ; ")
        connection.close()

    def tearDown(self):
        connection = psycopg2.connect("dbname='policy_optimizer_test' host='localhost' user='psyco' password='shit'")
        connection.set_isolation_level(0)
        cur = connection.cursor()
        cur.execute("drop table firewallrules")
        connection.close()

    def test_basic_postgres_aggregation(self):
        gpl = PostgresGPL(dbname="policy_optimizer_test", dbhost="localhost", dbpass="shit", dbuser="psyco")
        optimizer = PolicyOptimizer(gpl=gpl)
        optimizer.add_rule(FirewallRule(source='1.1.1.0/32', destination='1.1.1.4/32',
                                        protocol='tcp/80', action=FWACTION.ACCEPT))
        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='tcp/80', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.get_rules()[0].source, IPNetwork('1.1.1.0/31'))

        optimizer.add_rule(FirewallRule(source='1.1.1.0/31', destination='1.1.1.5/32',
                                        protocol='tcp/80', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.get_rules()[0].destination, IPNetwork('1.1.1.4/31'))

        optimizer.add_rule(FirewallRule(source='1.1.1.0/31', destination='1.1.1.4/31',
                                        protocol='tcp/443', action=FWACTION.ACCEPT))
        self.assertEqual(gpl.get_rules()[0].protocol, "tcp/80 tcp/443")

        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='tcp/443', action=FWACTION.ACCEPT))
        self.assertEqual(len(gpl.get_rules()), 1)

        optimizer.add_rule(FirewallRule(source='1.1.1.1/32', destination='1.1.1.4/32',
                                        protocol='udp/443', action=FWACTION.ACCEPT))
        self.assertEqual(len(gpl.get_rules()), 2)



