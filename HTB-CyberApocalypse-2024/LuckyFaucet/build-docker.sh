#!/bin/bash

set -ex

########### ENV VARS ###########
NAME=luckyfaucet
IMAGE=blockchain_${NAME}
FLAG="HTB{1_f0rg0r_s0m3_U}"
SHARED_SECRET="17bf3ae1-8020-4527-9edc-bfc64dd14fd3"
PUBLIC_IP="0.0.0.0"
TEAM_UUID=$(uuidgen)
SRV_PORT=8000
HANDLER_PORT=8002
################################

docker rm -f $IMAGE && \
docker build --tag=$IMAGE:latest ./challenge/ && \
docker run -it --rm \
    -e "NAME=$NAME" \
    -e "PYTHONPATH=/usr/lib/python3/" \
    -e "PUBLIC_IP=$PUBLIC_IP" \
    -e "TEAM_UUID=$TEAM_UUID" \
    -e "SRV_PORT=$SRV_PORT" \
    -e "HANDLER_PORT=$HANDLER_PORT" \
    -e "SHARED_SECRET=$SHARED_SECRET" \
    -e "FLAG=$FLAG" \
    -p "$SRV_PORT:$SRV_PORT" \
    -p "$HANDLER_PORT:$HANDLER_PORT" \
    --name $IMAGE \
    $IMAGE