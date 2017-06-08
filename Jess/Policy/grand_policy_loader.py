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
    # TODO: add __init__ with connection string or something.
    # TODO: probably requires inheriting class

    def load(self):
        # TODO: load from DB. this is stupidity
        return [FirewallRule(source='1.2.3.4', destination='1.2.3.5', protocol='icmp', action=FWACTION.ACCEPT),
                FirewallRule(source='1.2.3.5', destination='1.2.3.4', protocol='tcp/22', action=FWACTION.ACCEPT),
                FirewallRule(source='0.0.0.0/0', destination='0.0.0.0/0', protocol='tcp', action=FWACTION.REJECT)]
