from unittest import TestCase
from Jess.Endpoint.endpoint_policy_generator import EndpointPolicyGenerator
from Jess.Endpoint.managed_endpoint import ManagedEndpoint
from Jess.Endpoint.PolicyCommitMechanism import IPTablesCommitMechanism


class TestsEndpiontPolicyGenerator(TestCase):
    def test_empty_endpoint(self):
        epg = EndpointPolicyGenerator(ManagedEndpoint(ip='6.6.6.6', method='ssh', mechanism='iptables'))
        self.assertIsInstance(epg.managed_endpoint.mechanism, IPTablesCommitMechanism)
