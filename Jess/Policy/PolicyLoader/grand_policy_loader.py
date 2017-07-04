# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from Jess.Policy.firewall_rule import FirewallRule, FWACTION


# TODO: change from loader to DAL
class GrandPolicyLoader(object):
    @classmethod
    def identifiers(cls):
        return ['default', 'gpl']

    # TODO: add save methods
    def __init__(self, *args, **kwargs):
        self.rules = []
        args = list(args)
        args += kwargs.get('rules', [])
        for rule in args:
            if isinstance(rule, FirewallRule):
                self.rules.append(rule)
            elif isinstance(rule, dict):
                self.rules.append(FirewallRule(**rule))

    def load(self):
        return self.rules

    def get_rules(self, source=None, destination=None, protocol=None, action=None):
        rules = []
        for rule in self.rules:
            if (source is None or source in rule.source) and \
                    (destination is None or destination in rule.destination) and \
                    (protocol is None or rule.protocol == protocol) and \
                    (action is None or rule.action == action):
                rules.append(rule)
        return rules

    def update_rule(self, existing_rule, new_rule):
        index = self.rules.index(existing_rule)
        self.rules.pop(index)
        self.rules.insert(index, new_rule)

    def add_rule(self, new_rule):
        self.rules.append(new_rule)
