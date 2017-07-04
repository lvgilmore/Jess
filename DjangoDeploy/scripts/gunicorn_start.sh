#!/bin/bash
set -e

CONF_DIR=/container/conf
WSGI_FILE=/web/Web/wsgi.py
if [ ! -e "$WSGI_FILE" ]; then
    echo "Expected to find $WSGI_FILE"
    exit 1
fi

pushd ${CONF_DIR} >> /dev/null

exec gunicorn -c gunicorn_app.conf Web.wsgi

popd >> /dev/null
