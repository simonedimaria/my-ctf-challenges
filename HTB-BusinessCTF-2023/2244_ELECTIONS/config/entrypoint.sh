#!/bin/bash

set -ex

mkdir -p /var/log/ctf/

for f in /startup/*; do
    echo "[+] running $f"
    bash "$f"
done

tail -f /var/log/ctf/*