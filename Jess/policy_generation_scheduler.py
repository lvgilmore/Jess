# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from multiprocessing import Pool

from Jess.Endpoint.endpoint_policy_generator import EndpointPolicyGenerator
from Jess.Endpoint.managed_endpoint import ManagedEndpoint
from Jess.configs import number_of_concurent_procs


class PolicyGenerationScheduler(object):
    # TODO: read the todos of grand_policy_loader, exactly the same
    def __init__(self):
        self.managed_endpoints = self.load_endpoints()
        thread_pool = Pool(number_of_concurent_procs)
        thread_pool.map(EndpointPolicyGenerator, self.managed_endpoints)

    # TODO: change to something real, which means endpoint loader (much like gpl)
    def load_endpoints(self):
        return [ManagedEndpoint(ip='1.2.3.4', methods='ssh', mechanism='iptables'),
                ManagedEndpoint(ip='1.2.3.5', methods='ssh', mechanism='iptables')]
