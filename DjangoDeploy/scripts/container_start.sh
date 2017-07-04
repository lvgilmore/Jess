#!/bin/bash
set -e

pushd /web >> /dev/null

# Set up Django app
sudo -u app_user python3 /web/manage.py migrate --noinput
sudo -u app_user python3 /web/manage.py collectstatic --noinput

popd >> /dev/null

# Allow users to provide their own start script
USER_START_SCRIPT=/container/scripts/start.sh
if [ -e "$USER_START_SCRIPT" ]; then
    source ${USER_START_SCRIPT}
fi

# Start supervisor
supervisord -n
