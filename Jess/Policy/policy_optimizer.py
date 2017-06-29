# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from firewall_rule import FirewallRule, parse_protocol
from ipaddr import IPNetwork


class IPError(ArithmeticError):
    pass


def aggregate(ip1, ip2):
    ip1 = IPNetwork(ip1)
    ip2 = IPNetwork(ip2)

    if ip1.netmask == ip2.netmask and ip1.Supernet().Contains(ip2):
        return ip1.Supernet()
    else:
        raise IPError()


class PolicyOptimizer(object):
    def __init__(self, gpl):
        self.gpl = gpl

    def add_rule(self, requested_rule):
        # first case: source and dest already exists
        existing_rules = self.gpl.get_rules(source=requested_rule.source, destination=requested_rule.destination)
        for existing_rule in existing_rules:
            if requested_rule.protocol in existing_rule.protocol:
                return True
            elif parse_protocol(requested_rule.protocol)['protocol'] == parse_protocol(existing_rule.protocol)['protocol'] \
                    and requested_rule.action == existing_rule.action:
                return self.gpl.update_rule(
                    existing_rule,
                    FirewallRule(source=existing_rule.source, destination=existing_rule.destination,
                                 protocol=("{e} {r}".format(e=existing_rule.protocol, r= requested_rule.protocol)),
                                 action=existing_rule.action)
                )
        if len(existing_rules) > 1:
            # if we got here, than src and dest exists but not protocol
            return self.gpl.add_rule(requested_rule)

        # second case: source can be aggregated to existing rule
        # TODO: this is very naive implementation. ironically, it needs to be optimized :)
        for existing_rule in self.gpl.get_rules(destination=requested_rule.destination, protocol=requested_rule.protocol):
            try:
                return self.gpl.update_rule(
                    existing_rule,
                    FirewallRule(source=aggregate(existing_rule.source, requested_rule.source),
                                 destination=existing_rule.destination, protocol=existing_rule.protocol,
                                 action=existing_rule.action)
                )
            except IPError:
                pass

        # third case: destination can be aggregated to existing rule
        for existing_rule in self.gpl.get_rules(source=requested_rule.source,
                                                protocol=requested_rule.protocol):
            try:
                return self.gpl.update_rule(
                    existing_rule,
                    FirewallRule(destination=aggregate(existing_rule.destination, requested_rule.destination),
                                 source=existing_rule.source, protocol=existing_rule.protocol,
                                 action=existing_rule.action)
                )
            except IPError:
                pass

        # when all else fails, simply add the f** rule
        return self.gpl.add_rule(requested_rule)
