FROM ghcr.io/foundry-rs/foundry:nightly-c13d42e850da353c0856a8b0d4123e13cc40045d as foundry

FROM blockscout/blockscout:6.9.0 AS blockscout_backend

FROM ghcr.io/blockscout/frontend:v1.36.1 AS blockscout_frontend

FROM hexpm/elixir:1.17.3-erlang-27.1-alpine-3.20.3 as runner

COPY ./backend/requirements.txt /tmp/requirements.txt

RUN apk add --no-cache git 
RUN apk --no-cache --update add \
    linux-headers \
    git \
    gcompat \
    libstdc++ \
    bash \
    python3 \
    py3-pip \
    nodejs \
    curl \
    socat \
    envsubst \
    postgresql15 \
    redis \
    nginx \
    supervisor

RUN python3 -m pip install --break-system-packages --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /tmp/requirements.txt

RUN addgroup -S blockscout && adduser -S blockscout -G blockscout
RUN addgroup -S ctf && adduser -S ctf -G ctf -s /bin/bash

COPY ./backend/entrypoint.sh /
COPY ./backend/eth_sandbox/ /usr/lib/python/eth_sandbox/
COPY ./backend/contracts/ /home/ctf/backend/contracts/
COPY ./backend/scripts/ /home/ctf/backend/scripts/

COPY ./config/ /startup/
COPY ./config/nginx.conf /etc/nginx/templates/default.conf.template
COPY ./config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY ./config/blockscout-db-data /var/lib/postgresql/data/

COPY --from=blockscout_backend /app/ /home/ctf/blockscout_backend/
COPY --from=blockscout_frontend /app/ /home/ctf/blockscout_frontend/

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/chisel /usr/local/bin/chisel

RUN chmod +x /entrypoint.sh \
    && mkdir -p /var/log/ctf/ \
    && touch /var/log/ctf/challenge_bot.log \
    && touch /var/log/ctf/anvil_output.log \ 
    && chown -R ctf:ctf /var/log/ctf/ \
    && chmod 777 /var/log/ctf/ \
    && chown -R ctf:ctf /home/ctf/ \
    && chown -R blockscout:blockscout /home/ctf/blockscout_backend/ \
    && chown -R blockscout:blockscout /home/ctf/blockscout_frontend/ \
    && chmod -R 777 /home/ctf/blockscout_frontend/public \
    && chmod -R 777 /home/ctf/blockscout_frontend/.next \
    && chmod -R 777 /home/ctf/blockscout_frontend/deploy \
    && mkdir -p /run/postgresql/ \
    && chown -R postgres:postgres /run/postgresql/ \
    && chown -R postgres:postgres /var/lib/postgresql/ \
    && su postgres -c "chmod 0700 /var/lib/postgresql/data/"

RUN true && \
    cd /home/ctf/backend/contracts/ && \
    forge build --out ./compiled && \
    true

ENV PYTHONPATH=/usr/lib/python/
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
EXPOSE 5000
#EXPOSE 8080

USER root
WORKDIR /home/ctf/
COPY ./config/.env.blockscout.evaluated .
ENTRYPOINT [ "/entrypoint.sh" ]