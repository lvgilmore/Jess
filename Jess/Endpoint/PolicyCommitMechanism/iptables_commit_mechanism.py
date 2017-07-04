# /usr/bin/python
# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from Jess.Endpoint.PolicyCommitMechanism import PolicyCommitMechanism
from Jess.Policy.firewall_rule import FWACTION, parse_protocol


class IPTablesCommitMechanism(PolicyCommitMechanism):
    @classmethod
    def identifiers(cls):
        return ['default', 'iptables']

    @staticmethod
    def _parse_command_protocol(protocol):
        p = parse_protocol(protocol=protocol)
        if 'dport' in p:
            return "{protocol} --dport {dport}".format(protocol=p['protocol'], dport=p['dport'])
        else:
            return "{protocol}".format(protocol=p['protocol'])

    @staticmethod
    def _parse_display_protocol(protocol):
        p = parse_protocol(protocol=protocol)
        if 'dport' in p:
            return p['protocol'], "{protocol} dpt:{dport}".format(protocol=p['protocol'], dport=p['dport'])
        else:
            return p['protocol'], "{protocol}".format(protocol=p['protocol'])

    @staticmethod
    def _add_rule(formal_rule, chain):
        action = "iptables -{insert_or_append} {chain} --source {source} --destination {destination} " \
                 "-p {protocol_args} -j {action}".format(
                    insert_or_append='I' if formal_rule.action == FWACTION.ACCEPT else 'A',
                    chain=chain,
                    source=formal_rule.source,
                    destination=formal_rule.destination,
                    protocol_args=IPTablesCommitMechanism._parse_command_protocol(formal_rule.protocol),
                    action=formal_rule.s_action()
        )
        return action

    def add_incoming_rule(self, formal_rule):
        action = IPTablesCommitMechanism._add_rule(formal_rule=formal_rule, chain='INPUT')
        super(IPTablesCommitMechanism, self).add_incoming_rule(formal_rule=formal_rule)
        return action

    def add_outgoing_rule(self, formal_rule):
        action = IPTablesCommitMechanism._add_rule(formal_rule=formal_rule, chain='OUTPUT')
        super(IPTablesCommitMechanism, self).add_outgoing_rule(formal_rule=formal_rule)
        return action

    def dynamic_representation(self):
        representation = ""
        for chain in [(self.incoming_rules, "INPUT"),
                      (self.forwarding_rules, "FORWARD"),
                      (self.outgoing_rules, "OUTPUT")]:
            for rule in chain[0]:
                representation += self._add_rule(rule, chain[1])
                representation += "\n"
        return representation.strip()

    def __repr__(self):
        representation = ""
        for chain, rules in [["OUTPUT", self.outgoing_rules],
                            ["FORWARD", self.forwarding_rules],
                            ["INPUT", self.incoming_rules]]:
            representation += "Chain {chain}\n".format(chain=chain)
            for rule in rules:
                p, a = IPTablesCommitMechanism._parse_display_protocol(rule.protocol)
                representation += "{action}\t{protocol}\t--\t{source}\t{destination}\t{args}\n".format(
                    action=rule.s_action(),
                    protocol=p,
                    source=rule.source,
                    destination=rule.destination,
                    args=a
                )
            representation += "\n"
        return representation

    def __str__(self):
        return self.__repr__()
