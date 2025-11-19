#!/bin/sh

set -ex
set -o allexport

########### ENV VARS ###########
FLAG=HTB{g4sL1ght1nG_th3_VCNK_its_GreatBl@ck0Ut_4ll_ov3r_ag4iN}
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
ANVIL_LOGFILE="/var/log/ctf/anvil_output.log"
################################

touch ${ANVIL_LOGFILE} && chown ctf:ctf ${ANVIL_LOGFILE} && \
supervisord -c /startup/supervisord.conf -u root && \
sleep 2 && \
tail -f /var/log/ctf/*.log
