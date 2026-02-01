#!/bin/bash
set -e
# When running as root (e.g. Railway), ensure /data is writable by linuxbrew then run app as linuxbrew
if [ "$(id -u)" = "0" ]; then
  chown -R linuxbrew:linuxbrew /data 2>/dev/null || true
  exec gosu linuxbrew "$@"
fi
exec "$@"
