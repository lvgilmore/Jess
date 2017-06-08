# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from Jess.Policy.firewall_rule import FirewallRule
from Jess.configs import grand_policy_loader


class EndpointPolicyGenerator(object):
    def __init__(self, managed_endpoint):
        self.managed_endpoint = managed_endpoint
        grand_policy = grand_policy_loader().load()
        self._init_policy(grand_policy)

    def _init_policy(self, grand_policy):
        for rule in grand_policy:
            if self.managed_endpoint.ip in rule.source:
                self.managed_endpoint.mechanism.add_outgoing_rule(
                    FirewallRule(source=self.managed_endpoint.ip, destination=rule.destination,
                                 protocol=rule.protocol, action=rule.action)
                )
            if self.managed_endpoint.ip in rule.destination:
                self.managed_endpoint.mechanism.add_incoming_rule(
                    FirewallRule(source=rule.source, destination=self.managed_endpoint.ip,
                                 protocol=rule.protocol, action=rule.action)
                )

    def apply_policy(self, grand_policy=None):
        if grand_policy is not None:
            self._init_policy(grand_policy)
        self.managed_endpoint.method.apply()
