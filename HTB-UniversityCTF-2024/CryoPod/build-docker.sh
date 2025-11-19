#!/bin/bash

set -ex

########### ENV VARS ###########
NAME=cryopod
IMAGE=blockchain_${NAME}
FLAG=HTB{h3ll0_ch41n_sc0ut3r}
PUBLIC_IP=127.0.0.1
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
LOCAL_RPC_URL=http://localhost:${LOCAL_RPC_PORT}/
PUBLIC_RPC_PORT=8888
FRONTEND_PORT=8080
################################

docker rm -f $IMAGE
docker build --tag=$IMAGE:latest ./challenge/ && \
docker run --rm -it \
    -p "$PUBLIC_RPC_PORT:$LOCAL_RPC_PORT" \
    -p "$FRONTEND_PORT:$FRONTEND_PORT" \
    -p "$HANDLER_PORT:$HANDLER_PORT" \
    --name $IMAGE \
    $IMAGE:latest
