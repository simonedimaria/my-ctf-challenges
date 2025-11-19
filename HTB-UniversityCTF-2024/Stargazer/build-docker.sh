#!/bin/bash

docker rm -f $IMAGE
docker build --tag=$IMAGE:latest ./challenge/ && \
docker run --rm -it \
    -p "$PUBLIC_RPC_PORT:$LOCAL_RPC_PORT" \
    -p "$FRONTEND_PORT:$FRONTEND_PORT" \
    -p "$HANDLER_PORT:$HANDLER_PORT" \
    --name $IMAGE \
    $IMAGE:latest
