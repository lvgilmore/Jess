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


class GrandPolicyLoader(object):
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
