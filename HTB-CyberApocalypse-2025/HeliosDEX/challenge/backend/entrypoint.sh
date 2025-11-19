#!/bin/sh

set -ex
set -o allexport

########### ENV VARS ###########
FLAG=HTB{0n_Heli0s_tr4d3s_a_d3cim4l_f4d3s_and_f0rtun3s_ar3_m4d3}
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
ANVIL_LOGFILE="/var/log/ctf/anvil_output.log"
################################

touch ${ANVIL_LOGFILE} && chown ctf:ctf ${ANVIL_LOGFILE} && \
supervisord -c /startup/supervisord.conf -u root && \
sleep 2 && \
tail -f /var/log/ctf/*.log
