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

from Jess.Endpoint.PolicyApplicationMethod.abstract_policy_application import AbstractPolicyApplication


class SSHPolicyAplication(AbstractPolicyApplication):
    @classmethod
    def identifiers(cls):
        return ['default', 'ssh']

    def __init__(self, managed_endpoint):
        super(SSHPolicyAplication, self).__init__(managed_endpoint)

    def apply(self):
        super(SSHPolicyAplication, self).apply()
        commands = ""
        commands += self.clean()
        for line in self.managed_endpoint.mechanism.dynamic_representation().split('\n'):
            commands += "ssh {ip} {line}\n".format(ip=self.managed_endpoint.ip, line=line)
        return commands.strip()

    def clean(self):
        # TODO: very unelegant, need flush that is independent from mechanism
        return "ssh {ip} iptables -F \n".format(ip=self.managed_endpoint.ip)
