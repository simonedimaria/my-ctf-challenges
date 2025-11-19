import threading
import time
from typing import List, Dict, Any
from logging import Logger
from web3 import Web3
from web3.contract import Contract
from .utils import w3_send_tx


class EVMBot(threading.Thread):
    """Represents a simulated user (bot) that sends transactions."""

    def __init__(self, bot_id: int, bot_addr: str,
                 w3: Web3, target_contract: Contract, function_sig: str, args: List[Any], tx_options: Dict[str, Any],
                 private_key: str, rpc_url: str,
                 max_retries: int, retry_interval: int, logger: Logger) -> None:
        """
        Initializes a new EVMBot instance.
        
        Parameters:
            bot_id (int): The bot's unique identifier.
            bot_addr (str): The bot's Ethereum address.
            w3 (Web3): An initialized Web3 instance.
            target_contract (Contract): An instance of web3.contract.Contract.
            function_sig (str): The function signature of the target contract function.
            args (List[Any]): The arguments to pass to the target contract function.
            tx_options (Dict[str, Any]): Transaction parameters like 'gas', 'gasPrice', etc.
            
            private_key (str): The bot's private key.
            rpc_url (str): The RPC URL of the Ethereum node.
            max_retries (int): The maximum number of transaction retries.
            retry_interval (int): The interval between transaction retries.
            logger (Logger): The logger instance.
        """
        super().__init__(daemon=True, name=f"Bot-{bot_id}")
        self.bot_id = bot_id
        self.bot_addr = bot_addr
        self.w3 = w3
        self.target_contract = target_contract
        self.function_sig = function_sig
        self.args = args
        self.tx_options = tx_options
        self.private_key = private_key
        self.rpc_url = rpc_url
        self.max_retries = max_retries
        self.retry_interval = retry_interval
        self.logger = logger

    def run(self) -> bool:
        self.logger.info(f"{self.name} started.")
        retries = 0
        while retries <= self.max_retries:
            success, tx_hash = w3_send_tx(
                self.w3, self.target_contract, self.function_sig, self.args, self.tx_options,
                self.private_key, self.logger
            )
            if success:
                self.logger.info(f"[{self.name}] Transaction successful: {tx_hash}")
                return True
            else:
                wait_time = self.retry_interval
                self.logger.warning(f"[{self.name}] Retrying transaction in {wait_time} seconds (Attempt {retries + 1}/{self.max_retries})...")
                time.sleep(wait_time)
                retries += 1
        return False
