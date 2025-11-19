#!/bin/sh

set -ex
set -o allexport

########### ENV VARS ###########
NAME=eldorion
IMAGE=blockchain_${NAME}
FLAG=HTB{w0w_tr1pl3_hit_c0mbo_ggs_y0u_defe4ted_Eld0r10n}
PUBLIC_IP=127.0.0.1
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
LOCAL_RPC_URL=http://localhost:${LOCAL_RPC_PORT}/
PUBLIC_RPC_PORT=8888
FRONTEND_PORT=8080
################################

touch /var/log/ctf/${ANVIL_LOGFILE} && \
chown ctf:ctf /var/log/ctf/${ANVIL_LOGFILE} && \
supervisord -c /startup/supervisord.conf -u root && \
sleep 2 && \
tail -f /var/log/ctf/*.log
