# !/usr/bin/env python3
# eth_sandbox/config.py

import os

class Config:
    PUBLIC_IP: str = os.getenv("PUBLIC_IP", "localhost")
    LOCAL_RPC_PORT: int = int(os.getenv("LOCAL_RPC_PORT", 5000))
    PUBLIC_RPC_PORT: int = int(os.getenv("PUBLIC_RPC_PORT", 8888))
    HANDLER_PORT: int = int(os.getenv("HANDLER_PORT", 8000))
    FRONTEND_PORT: int = int(os.getenv("FRONTEND_PORT", 8080))
    ANVIL_LOGFILE: str = "/var/log/ctf/anvil_output.log"
    FLAG: str = os.getenv("FLAG", "HTB{placeholder}")
    
    # @TODO: change this
    ALLOWED_NAMESPACES: list = ["web3", "eth", "net"]
    RECEIPT_POLL_INTERVAL: float = 0.1
    N_ACCOUNTS: int = 2
    N_BOTS: int = 0
    DEPLOYER_BALANCE: int = 100 # ETH
    PLAYER_BALANCE: int = 10 # ETH
    BOT_BALANCE: int = 0 # ETH
    SETUP_CONTRACT_BALANCE: int = 0 # ETH
