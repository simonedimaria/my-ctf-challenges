FROM ghcr.io/foundry-rs/foundry:v1.1.0 as foundry

FROM python:3.12-slim-bookworm as runner

COPY ./backend/requirements.txt /tmp/requirements.txt

RUN apt update && \
    apt install -y \
    curl \
    git \
    socat \
    supervisor

RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /tmp/requirements.txt

RUN useradd -m ctf -s /bin/bash

COPY ./backend/entrypoint.sh /
COPY ./backend/eth_sandbox/ /usr/lib/python/eth_sandbox/
COPY ./backend/contracts/ /home/ctf/backend/contracts/
COPY ./backend/scripts/ /home/ctf/backend/scripts/

COPY ./config/ /startup/
COPY ./config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/chisel /usr/local/bin/chisel

RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/log/ctf/ && \
    chown -R ctf:ctf /var/log/ctf/ && \
    chmod 777 /var/log/ctf/ && \
    chown -R ctf:ctf /home/ctf/

USER ctf
SHELL ["/bin/bash", "-c"]

ENV PYTHONPATH=/usr/lib/python/
ENV PYTHONUNBUFFERED=1

RUN true \
    && cd /home/ctf/backend/contracts/ \
    && forge build --out ./compiled \
    && true

EXPOSE 8000
EXPOSE 5000

USER root
WORKDIR /home/ctf/
ENTRYPOINT [ "/entrypoint.sh" ]
