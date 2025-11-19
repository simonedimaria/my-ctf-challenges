#!/bin/sh

set -ex

set -o allexport
########### ENV VARS ###########
export NAME=cryopod
export IMAGE=blockchain_${NAME}
export FLAG=HTB{h3ll0_ch41n_sc0ut3r}
export PUBLIC_IP=127.0.0.1
export HANDLER_PORT=8000
export LOCAL_RPC_PORT=5000
export LOCAL_RPC_URL=http://localhost:${LOCAL_RPC_PORT}/
export PUBLIC_RPC_PORT=8888
export FRONTEND_PORT=8080
source .env.blockscout.evaluated
################################
set +o allexport

sleep 2 && \
envsubst '${BACK_PROXY_PASS} ${FRONT_PROXY_PASS}' < /etc/nginx/templates/default.conf.template > /etc/nginx/nginx.conf && \
supervisord -c /startup/supervisord.conf -u root && \
tail -f /var/log/ctf/*.log
