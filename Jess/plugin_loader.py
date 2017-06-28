# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import inspect
import os
import pkgutil
from Jess.Endpoint import PolicyApplicationMethod
from Jess.Endpoint import PolicyCommitMechanism
from Jess.Policy import PolicyLoader

# dynamically load classes and such
COMMIT_METHOD = {}
COMMIT_MECHANISM = {}
POLICY_LOADER = {}
dynamics = {PolicyApplicationMethod: COMMIT_METHOD,
            PolicyCommitMechanism: COMMIT_MECHANISM,
            PolicyLoader: POLICY_LOADER}

for package in dynamics.keys():
    modules = [name for _, name, _ in pkgutil.iter_modules([os.path.dirname(package.__file__)])]
    for m in modules:
        mod = __import__('{}.{}'.format(package.__name__, m), fromlist=['*'])
        mod_classes = inspect.getmembers(mod, inspect.isclass)
        for c in mod_classes:
            try:
                for identifier in c[1].identifiers():
                    dynamics[package][identifier] = c[1]
            except AttributeError:
                pass
