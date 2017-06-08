#! /usr/bin/python

# TODO: there's got to be a better way

from Jess.Endpoint.PolicyCommitMechanism.policy_commit_mechanism import PolicyCommitMechanism
from Jess.Endpoint.PolicyCommitMechanism.iptables_commit_mechanism import IPTablesCommitMechanism

COMMIT_MACHANSIM = {'default': PolicyCommitMechanism,
                    'iptables': IPTablesCommitMechanism}
