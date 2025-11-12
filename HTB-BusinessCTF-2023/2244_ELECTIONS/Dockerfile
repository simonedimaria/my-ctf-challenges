FROM debian:bookworm as ctf-base

# install xinetd and python, create ctf user
RUN true \
    && mkdir -p /var/log/ctf/ /startup/ \
    && apt update \
    && apt install -y xinetd tini curl git python3 python3-pip \
    && rm -rf /var/cache/apt/archives/ \
    && useradd -m ctf \
    && true

RUN true \
    && curl -L https://foundry.paradigm.xyz | bash \
    && bash -c "source /root/.bashrc && foundryup" \
    && chmod 755 -R /root \
    && true

COPY ./config/98-start-gunicorn /startup
COPY ./config/entrypoint.sh /entrypoint.sh

FROM ctf-base as challenge

# install sass 
WORKDIR /opt
RUN curl -L https://github.com/sass/dart-sass/releases/download/1.57.1/dart-sass-1.57.1-linux-x64.tar.gz -o dart-sass-1.57.1-linux-x64.tar.gz \
    && tar -xvf dart-sass-1.57.1-linux-x64.tar.gz \
    && rm dart-sass-1.57.1-linux-x64.tar.gz

# Setup app
RUN mkdir -p /app

WORKDIR /app

COPY challenge .

ENV PYTHONPATH /usr/lib/python
RUN rm -rf /usr/lib/python3.*/EXTERNALLY-MANAGED
RUN python3 -m pip install -r /app/requirements.txt 

ENV HTTP_PORT=1337
EXPOSE 1337

COPY ./challenge/contracts /tmp/contracts

# compile all
RUN true \
    && /opt/dart-sass/sass /app/static/css/main.scss /app/static/css/main.css \
    && cd /tmp \
    && /root/.foundry/bin/forge build --optimizer-runs 1 --via-ir --out /home/ctf/compiled \
    && rm -rf /tmp/contracts \
    && true

RUN echo "App setupped successfully" >> /var/log/ctf/app.log

ENTRYPOINT [ "tini", "--" ]
CMD [ "/entrypoint.sh" ]