FROM python:3.9-slim-bullseye as ctf-base

# install xinetd, create ctf user
RUN true \
    && mkdir /var/log/ctf/ /startup/ \
    && apt update \
    && apt install -y xinetd tini curl git \
    && rm -rf /var/cache/apt/archives/ \
    && useradd -m ctf \
    && true

# copy xinetd config and startup scripts
COPY ./startup/ /startup/
COPY entrypoint.sh /entrypoint.sh


#################
#    BACKEND    #
#################
FROM ctf-base as backend

# setup foundry and compile contracts
RUN true \
    && curl -L https://foundry.paradigm.xyz | bash \
    && bash -c "source /root/.bashrc && foundryup" \
    && chmod 755 -R /root/ \
    && true
 
COPY ./backend/contracts/ /tmp/contracts/

RUN true \
    && cd /tmp/contracts/ \
    && /root/.foundry/bin/forge build --out /home/ctf/backend/compiled-contracts/ \
    && rm -rf /tmp/contracts/ \
    && true

# setup challenge handler
COPY ./requirements.in /tmp/
#RUN rm -rf /usr/lib/python3.*/EXTERNALLY-MANAGED
RUN pip install pip-tools && \
    pip-compile /tmp/requirements.in -o /tmp/requirements.txt && \
    pip install -r /tmp/requirements.txt
COPY ./backend/chall_handler/eth_sandbox/ /usr/lib/python3/eth_sandbox/
COPY ./backend/chall_handler/handler.py /home/ctf/backend/handler.py
COPY ./backend/chall_handler/start-handler.sh /home/ctf/backend/chall_handler/

WORKDIR /home/ctf/
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh"]
