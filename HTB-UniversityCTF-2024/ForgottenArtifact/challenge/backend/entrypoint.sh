#!/bin/sh

set -ex

touch /var/log/ctf/${ANVIL_LOGFILE} && \
chown ctf:ctf /var/log/ctf/${ANVIL_LOGFILE} && \
supervisord -c /startup/supervisord.conf -u root && \
sleep 2 && \
tail -f /var/log/ctf/*.log
