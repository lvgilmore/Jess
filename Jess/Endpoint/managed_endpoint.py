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
from Jess.Endpoint.PolicyApplicationMethod import COMMIT_METHOD
from ipaddr import IPAddress

from Jess.Endpoint.PolicyCommitMechanism.iptables_commit_mechanism import IPTablesCommitMechanism


class ManagedEndpoint(object):
    # TODO: consider several IPs and several CommitMechansms
    def __init__(self, ip, methods, mechanism=IPTablesCommitMechanism(), strict=True):
        self.ip = IPAddress(ip)
        self.strict = strict
        self.methods = []
        if isinstance(methods, str):
            methods = [methods]
        else:
            try:
                for m in methods:
                    pass
            except TypeError:
                methods = [methods]
        for m in methods:
            if m in COMMIT_METHOD:
                self.methods.append(COMMIT_METHOD[m](self))
            else:
                self.methods.append(m)
        if isinstance(mechanism, str):
            self.mechanism = COMMIT_MACHANSIM[mechanism]()
        else:
            self.mechanism = mechanism

    def apply(self):
        self.method.apply(self.mechanism)
