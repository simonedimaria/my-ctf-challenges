import logging
import sys
import json
import os
import subprocess
import requests
from typing import List, Tuple, Dict, Any
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import TransactionNotFound


def setup_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("ChallengeBot")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger

def load_env() -> Dict[str, Any]:
    env = {
        "LOCAL_RPC_URL": os.getenv("LOCAL_RPC_URL"),
        "BOT_MAX_RETRIES": int(os.getenv("BOT_MAX_RETRIES", "5")),
        "BOT_RETRY_INTERVAL": float(os.getenv("BOT_RETRY_INTERVAL", "2")),
        "BOT_LOG_FILE": os.getenv("BOT_LOG_FILE", "/var/log/ctf/challenge_bot.log")
    }
    if not env["LOCAL_RPC_URL"]:
        raise ValueError("LOCAL_RPC_URL is not set in the environment variables.")
    return env

def is_node_running() -> bool:
    env = load_env()
    try:
        w3 = Web3(Web3.HTTPProvider(env["LOCAL_RPC_URL"]))
        is_healthy = w3.is_connected()
    except requests.exceptions.Timeout:
        is_healthy = False
    return is_healthy

def get_node_info() -> Dict:
    if not is_node_running():
        return {}
    try:
        with open('/home/ctf/backend/node_info.json', 'r') as f:
            node_info = json.loads(f.read())
    except FileNotFoundError:
        return None
    return node_info

def get_contracts_instances(
    w3: Web3,
    contracts_dir: str,
    contract_address_mapping: Dict[str, str],
    logger: logging.Logger
) -> Dict[str, Contract]:
    if not is_node_running():
        return {}
    
    contracts = {}
    node_info = get_node_info()
    
    for entry in os.scandir(contracts_dir):
        if entry.is_dir() and entry.name.endswith(".sol"):
            contract_sol_dir = entry.path
            contract_name = entry.name.replace(".sol", "")
            contract_json_path = os.path.join(contract_sol_dir, f"{contract_name}.json")

            if not os.path.isfile(contract_json_path):
                logger.warning(f"JSON file for contract '{contract_name}' not found at {contract_json_path}. Skipping.")
                continue

            logger.debug(f"Processing contract '{contract_name}' from {contract_json_path}.")

            try:
                with open(contract_json_path, "r") as f:
                    contract_data = json.load(f)

                abi = contract_data.get("abi")
                if abi is None:
                    logger.error(f"ABI not found in {contract_json_path}. Skipping contract '{contract_name}'.")
                    continue

                address_key = contract_address_mapping.get(contract_name)
                if address_key is None:
                    logger.error(f"No address mapping found for contract '{contract_name}'. Skipping.")
                    continue

                contract_address = node_info.get(address_key)
                if contract_address is None:
                    logger.error(f"Address '{address_key}' not found in node_info for contract '{contract_name}'. Skipping.")
                    continue

                contract_instance = w3.eth.contract(address=contract_address, abi=abi)
                contracts[contract_name] = contract_instance
                logger.info(f"Loaded contract '{contract_name}' @ address {contract_address}.")

            except json.JSONDecodeError as jde:
                logger.error(f"JSON decoding error in {contract_json_path}: {jde}. Skipping contract '{contract_name}'.")
                continue
            except Exception as e:
                logger.exception(f"Unexpected error while processing contract '{contract_name}': {e}. Skipping.")
                continue

    if not contracts:
        logger.error(f"No valid contracts loaded from directory: {contracts_dir}")
        raise ValueError(f"No valid contracts found in {contracts_dir}")

    return contracts

def get_bots() -> List[Tuple[str, str]]:
    if not is_node_running():
        return []
    
    node_info = get_node_info()
    bots = node_info['bots']
    return bots
    
def csend(target_contract: str, fn: str, args: List[str], options: Dict[str, Any],
          rpc_url: str, private_key: str, logger: logging.Logger) -> Tuple[bool, str]:
    base_command = ["cast", "send", target_contract, fn] + args

    for key, value in options.items():
        option_key = f"--{key.replace('_', '-')}"
        base_command.extend([option_key, str(value)])

    base_command.extend(["--rpc-url", rpc_url, "--private-key", private_key])

    command_str = ' '.join(base_command)
    logger.debug(f"Executing command: {command_str}")

    try:
        result = subprocess.run(
            base_command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.info(f"Transaction successful: {result.stdout.strip()}")
        tx_hash = result.stdout.strip().split()[0]
        return True, tx_hash
    except subprocess.CalledProcessError as e:
        logger.error(f"Transaction failed: {e.stderr.strip()}")
        return False, "0x"
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        return False, "0x"

def w3_send_tx(
    w3: Web3,
    contract: Contract,
    function_signature: str,
    args: List[Any],
    tx_options: Dict[str, Any],
    private_key: str,
    logger: logging.Logger
) -> Tuple[bool, str]:
    """
    Sends a transaction to a specified smart contract function.

    Parameters:
        w3 (Web3): An initialized Web3 instance.
        contract (Contract): An instance of web3.contract.Contract.
        function_signature (str): The full signature of the contract function (e.g., "transfer(address,uint256)").
        args (List[Any]): Arguments to pass to the contract function.
        tx_options (Dict[str, Any]): Transaction parameters like 'gas', 'gasPrice', etc.
        private_key (str): The private key for signing the transaction.
        logger (logging.Logger): Logger for logging information and errors.

    Returns:
        Tuple[bool, str]: A tuple containing a success flag and the transaction hash or error message.
    """
    is_healthy = is_node_running()
    if not is_healthy:
        logger.error("Node is not running. Please start the node before sending transactions.")
        return False, "Node is not running."

    try: # get the contract function
        contract_function = contract.get_function_by_signature(function_signature)(*args)
        logger.debug(f"Retrieved contract function '{function_signature}'.")
    except Exception as e:
        logger.exception(f"Failed to get contract function '{function_signature}': {e}")
        return False, str(e)

    try: # preparing transaction parameters
        account_address = Account.from_key(private_key).address
        nonce = w3.eth.get_transaction_count(account_address)
        tx = {
            'nonce': nonce,
            'chainId': w3.eth.chain_id,
            'gas': tx_options.get('gas', 2000000),
            'gasPrice': tx_options.get('gasPrice', w3.to_wei('50', 'gwei')),
            **tx_options  # allow overriding defaults with tx_options
        }
        logger.debug(f"Transaction parameters: {tx}")
    except Exception as e:
        logger.exception(f"Failed to prepare transaction parameters: {e}")
        return False, str(e)

    try: # building the tx
        transaction_dict = contract_function.build_transaction(tx)
        logger.debug(f"Built transaction: {transaction_dict}")
    except Exception as e:
        logger.exception(f"Failed to build transaction: {e}")
        return False, str(e)

    try: # signing the tx
        signed_tx = w3.eth.account.sign_transaction(transaction_dict, private_key=private_key)
        logger.debug(f"Signed transaction: {signed_tx.hash.hex()}")
    except Exception as e:
        logger.exception(f"Failed to sign transaction: {e}")
        return False, str(e)

    try: # sending the tx
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        logger.info(f"Transaction sent with hash: {tx_hash.hex()}")
    except Exception as e:
        logger.error(f"Failed to send transaction: {e}")
        return False, str(e)

    try: # waiting the tx receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status == 1:
            logger.info(f"Transaction {tx_hash.hex()} succeeded.")
            return True, tx_hash.hex()
        else:
            logger.error(f"Transaction {tx_hash.hex()} failed.")
            return False, tx_hash.hex()
    except TransactionNotFound:
        logger.warning(f"Transaction {tx_hash.hex()} not found yet.")
        return True, tx_hash.hex()
    except Exception as e:
        logger.exception(f"Error while waiting for transaction receipt: {e}")
        return False, str(e)

def w3_call_view(
    w3: Web3,
    contract: Contract,
    function_signature: str,
    args: List[Any],
    logger: logging.Logger
) -> Tuple[bool, Any]:
    """
    Calls a smart contract function that does not modify state.

    Parameters:
        w3 (Web3): An initialized Web3 instance.
        contract (Contract): An instance of web3.contract.Contract.
        function_signature (str): The full signature of the contract function (e.g., "balanceOf(address)").
        args (List[Any]): Arguments to pass to the contract function.
        logger (logging.Logger): Logger for logging information and errors.

    Returns:
        Tuple[bool, Any]: A tuple containing a success flag and the function's return value or an error message.
    """
    is_healthy = is_node_running()
    if not is_healthy:
        logger.error("Node is not running. Please start the node before making calls.")
        return False, "Node is not running."

    try: # get the contract function
        contract_function = contract.get_function_by_signature(function_signature)(*args)
        logger.debug(f"Retrieved contract function '{function_signature}' with args {args}.")
    except Exception as e:
        logger.exception(f"Failed to get contract function '{function_signature}': {e}")
        return False, str(e)

    try: # calling the function
        result = contract_function.call()
        logger.info(f"Successfully called '{function_signature}' with result: {result}")
        return True, result
    except Exception as e:
        logger.exception(f"Failed to call contract function '{function_signature}': {e}")
        return False, str(e)
