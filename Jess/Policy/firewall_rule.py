# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from ipaddr import IPNetwork


# TODO: this is very very stupid. there's got to be a better way.
class FWACTION(object):
    ACCEPT = 0
    DROP = 1
    REJECT = 2


class FirewallRule(object):
    def __init__(self, source='0.0.0.0', destination='0.0.0.0', protocol='tcp/80', action=FWACTION.REJECT):
        self.source = IPNetwork(source)
        self.destination = IPNetwork(destination)
        self.protocol = protocol
        self.action = action

    # TODO: the stupidity continues
    def s_action(self):
        return {0: 'ACCEPT', 1: 'DROP', 2: 'REJECT'}[self.action]


class UnknownActionError(KeyError):
    pass
