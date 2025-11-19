#!/bin/bash

########### ENV VARS ###########
NAME=frontiermarketplace
IMAGE=blockchain_${NAME}
FLAG=HTB{g1mme_1t_b4ck}
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
