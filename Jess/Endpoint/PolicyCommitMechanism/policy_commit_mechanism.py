# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from Jess.Policy.firewall_rule import FWACTION, UnknownActionError


class PolicyCommitMechanism(object):
    @classmethod
    def identifiers(cls):
        return ['abstract']

    def __init__(self):
        self.incoming_rules = []
        self.outgoing_rules = []
        self.forwarding_rules = []

    @staticmethod
    def _add_rule(formal_rule, direction):
        if formal_rule.action == FWACTION.ACCEPT:
            direction.insert(0, formal_rule)
        elif formal_rule.action in [FWACTION.DROP, FWACTION.REJECT]:
            direction.append(formal_rule)
        else:
            raise UnknownActionError

    def add_incoming_rule(self, formal_rule):
        PolicyCommitMechanism._add_rule(formal_rule, self.incoming_rules)

    def add_outgoing_rule(self, formal_rule):
        PolicyCommitMechanism._add_rule(formal_rule, self.outgoing_rules)

    # TODO: add abstract __repr__ and dynamic_representation
