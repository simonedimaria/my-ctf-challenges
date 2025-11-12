IMAGE="2244_elections"
HTTP_PORT=1337
FLAG=HTB{n0th1ng_1s_h1dd3n_1n_th3_bl0ckch41n}

docker rm -f $IMAGE
docker build --tag=$IMAGE . && \
docker run -it \
    -e "HTTP_PORT=$HTTP_PORT" \
    -e "FLAG=$FLAG" \
    -p "$HTTP_PORT:$HTTP_PORT" \
    --name $IMAGE \
    $IMAGE