#!/bin/sh

set -ex
set -o allexport

########### ENV VARS ###########
FLAG=HTB{unkn0wn_1ntrud3r_1nsid3_Eld0r1a_gates}
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
ANVIL_LOGFILE="/var/log/ctf/anvil_output.log"
################################

touch ${ANVIL_LOGFILE} && chown ctf:ctf ${ANVIL_LOGFILE} && \
supervisord -c /startup/supervisord.conf -u root && \
sleep 2 && \
tail -f /var/log/ctf/*.log
