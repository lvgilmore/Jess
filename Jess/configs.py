# Copyright (C) 2017 Eitan Geiger and Sebastian Scheinkman
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from os import environ

# TODO: read from file
# general configs
number_of_concurent_procs = environ.get('CONCURRENCY', 16)
# db configs
dbname = environ.get('DB_NAME', 'grand_policy')
dbhost = environ.get('DB_HOST', 'localhost')
dbuser = environ.get('DB_USER', 'psyco')
dbpass = environ.get('DB_PASS', 'shit')
# plugin configs
grand_policy_loader = environ.get('GPL', 'postgres')
