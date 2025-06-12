#!/bin/bash
set -e

service apache2 start

exec /usr/local/bin/docker-entrypoint.sh "$@"
