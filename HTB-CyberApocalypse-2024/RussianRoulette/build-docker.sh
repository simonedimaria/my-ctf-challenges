#!/bin/bash

set -ex

########### ENV VARS ###########
NAME=russianroulette
IMAGE=blockchain_${NAME}
FLAG="HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}"
SHARED_SECRET="tmVxWHkgbGGg4sLe8tUWlDg5z2Ro8Rn0TGtIly6NRoELOhc1je7RZTHjk56mjlUJ"
PUBLIC_IP="0.0.0.0"
TEAM_UUID=$(uuidgen)
SRV_PORT=8001
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
