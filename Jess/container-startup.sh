#!/usr/bin/env bash

# initialize the database from python to spare the need of installing psql binary
python /Jess/utils/init_postgres_container.py

python /Jess/rabbit_consumer.ph
