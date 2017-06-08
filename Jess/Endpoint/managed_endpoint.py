# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from Jess.Endpoint.PolicyCommitMechanism import COMMIT_MACHANSIM
from ipaddr import IPAddress

from Jess.Endpoint.PolicyCommitMechanism.iptables_commit_mechanism import IPTablesCommitMechanism


class ManagedEndpoint(object):
    def __init__(self, ip, method, mechanism=IPTablesCommitMechanism()):
        self.ip = IPAddress(ip)
        # TODO: method should be a class of its own. it should have apply() method.
        self.method = method
        if isinstance(mechanism, str):
            self.mechanism = COMMIT_MACHANSIM[mechanism]()
        else:
            self.mechanism = mechanism
