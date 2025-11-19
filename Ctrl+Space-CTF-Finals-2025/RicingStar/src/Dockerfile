FROM node:24-alpine AS build
WORKDIR /app

COPY app/package.json ./
RUN npm install

COPY app/ .
RUN npm run build

WORKDIR /ext
COPY ext/ .
RUN npx web-ext build --overwrite-dest && mv web-ext-artifacts/*.zip ext.zip

FROM nginx:alpine AS runtime
WORKDIR /srv/app

RUN apk add --no-cache \
    python3 \
    py3-pip \
    supervisor \
    firefox \
    geckodriver

COPY bot/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY --from=build /app/build /usr/share/nginx/html
COPY --from=build /ext/ext.zip /srv/bot/ext.zip
COPY bot /srv/bot
COPY conf/nginx.conf /etc/nginx/conf.d/default.conf
COPY conf/supervisord.conf /etc/supervisord.conf

EXPOSE 80

CMD ["supervisord", "-c", "/etc/supervisord.conf"]
