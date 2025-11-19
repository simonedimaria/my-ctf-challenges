#!/bin/bash

########### ENV VARS ###########
NAME=forgottenartifact
IMAGE=blockchain_${NAME}
FLAG=HTB{y0u_c4n7_533_m3}
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
    -e PUBLIC_IP=$PUBLIC_IP \
    -e HANDLER_PORT=$HANDLER_PORT \
    -e PUBLIC_RPC_PORT=$PUBLIC_RPC_PORT \
    -e LOCAL_RPC_PORT=$LOCAL_RPC_PORT \
    -e LOCAL_RPC_URL=$LOCAL_RPC_URL \
    -e FLAG=$FLAG \
    --name $IMAGE \
    $IMAGE:latest
