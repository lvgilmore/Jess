from unittest import TestCase
from Jess.Endpoint.endpoint_policy_generator import EndpointPolicyGenerator
from Jess.Endpoint.managed_endpoint import ManagedEndpoint
from Jess.Endpoint.PolicyCommitMechanism import IPTablesCommitMechanism
from Jess.Policy.PolicyLoader.grand_policy_loader import GrandPolicyLoader
from Jess.Policy.firewall_rule import FWACTION


class TestsEndpiontPolicyGenerator(TestCase):
    def test_empty_endpoint(self):
        epg = EndpointPolicyGenerator(managed_endpoint=ManagedEndpoint(ip='6.6.6.6', methods='ssh',
                                                                       mechanism='iptables'),
                                      grand_policy_loader=GrandPolicyLoader(rules=[]))
        self.assertIsInstance(epg.managed_endpoint.mechanism, IPTablesCommitMechanism)

    def test_host(self):
        rules = [{'source': '6.6.6.6', 'destination': '1.1.1.1', 'protocol': 'tcp/80', 'action': FWACTION.ACCEPT},
                 {'source': '6.6.3.6', 'destination': '6.6.6.6', 'protocol': 'tcp/443', 'action': FWACTION.REJECT}]
        epg = EndpointPolicyGenerator(managed_endpoint=ManagedEndpoint(ip='6.6.6.6', methods='ssh',
                                                                       mechanism='iptables'),
                                      grand_policy_loader=GrandPolicyLoader(rules=rules))
        self.assertEqual(str(epg.managed_endpoint.mechanism),
                         ("Chain OUTPUT\n"
                          "ACCEPT\ttcp\t--\t6.6.6.6/32\t1.1.1.1/32\ttcp dpt:80\n"
                          "\n"
                          "Chain FORWARD\n"
                          "\n"
                          "Chain INPUT\n"
                          "REJECT\ttcp\t--\t6.6.3.6/32\t6.6.6.6/32\ttcp dpt:443\n"
                          "\n"))
        self.assertEqual(epg.managed_endpoint.methods[0].apply(),
                         "ssh 6.6.6.6 iptables -F \n"
                         "ssh 6.6.6.6 -A INPUT --source 6.6.3.6/32 --destination 6.6.6.6/32 -p tcp --dport 443 -j REJECT\n"
                         "ssh 6.6.6.6 -I OUTPUT --source 6.6.6.6/32 --destination 1.1.1.1/32 -p tcp --dport 80 -j ACCEPT")

    def test_network(self):
        rules = [{'source': '6.6.6.6', 'destination': '1.1.1.0/24', 'protocol': 'tcp/80', 'action': FWACTION.ACCEPT},
                 {'source': '6.6.0.0/16', 'destination': '6.6.6.0/24', 'protocol': 'tcp/443', 'action': FWACTION.REJECT}]
        epg = EndpointPolicyGenerator(managed_endpoint=ManagedEndpoint(ip='6.6.6.6', methods='ssh',
                                                                       mechanism='iptables'),
                                      grand_policy_loader=GrandPolicyLoader(rules=rules))
        self.assertEqual(str(epg.managed_endpoint.mechanism),
                         ("Chain OUTPUT\n"
                          "ACCEPT\ttcp\t--\t6.6.6.6/32\t1.1.1.0/24\ttcp dpt:80\n"
                          "REJECT\ttcp\t--\t6.6.6.6/32\t6.6.6.0/24\ttcp dpt:443\n"
                          "\n"
                          "Chain FORWARD\n"
                          "\n"
                          "Chain INPUT\n"
                          "REJECT\ttcp\t--\t6.6.0.0/16\t6.6.6.6/32\ttcp dpt:443\n"
                          "\n"))
        self.assertEqual(epg.managed_endpoint.methods[0].apply(),
                         "ssh 6.6.6.6 iptables -F \n"
                         "ssh 6.6.6.6 -A INPUT --source 6.6.0.0/16 --destination 6.6.6.6/32 -p tcp --dport 443 -j REJECT\n"
                         "ssh 6.6.6.6 -I OUTPUT --source 6.6.6.6/32 --destination 1.1.1.0/24 -p tcp --dport 80 -j ACCEPT\n"
                         "ssh 6.6.6.6 -I OUTPUT --source 6.6.6.6/32 --destination 6.6.6.0/24 -p tcp --dport 443 -j REJECT\n")
