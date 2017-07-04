#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd ${THIS_DIR}/.. >> /dev/null

echo "Building Django container"
sudo docker build -t shillaker/django-nginx .

popd >> /dev/null