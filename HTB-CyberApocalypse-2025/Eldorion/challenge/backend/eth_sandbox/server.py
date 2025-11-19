# !/usr/bin/env python3
# eth_sandbox/server.py

import os
import random
import subprocess
import signal
import json
import time
import requests
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from flask import Flask, Response, request, jsonify
from flask_cors import CORS, cross_origin
from web3 import Web3
from web3.types import TxReceipt
from web3.exceptions import TransactionNotFound
from eth_account import Account
from eth_account.hdaccount import generate_mnemonic
from eth_sandbox.config import Config
from eth_sandbox.exceptions import EthSandboxError

Account.enable_unaudited_hdwallet_features() # needed to generate wallet from mnemonic

logging.basicConfig(
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
    format="%(asctime)s [%(levelname)s] %(message)s"
)
app = Flask(__name__)
CORS(app)

INVALID_REQUEST = {
    "jsonrpc": "2.0",
    "error": {
        "code": -32600,
        "message": "invalid request",
    }
}

METHOD_NOT_ALLOWED = {
    "jsonrpc": "2.0",
    "error": {
        "code": -32601,
        "message": "method not allowed",
    }
}

def sendTransaction(web3: Web3, tx: Dict) -> Optional[TxReceipt]:
    if "gas" not in tx:
        estimated_gas = web3.eth.estimate_gas(tx)
        if estimated_gas is None or estimated_gas == 0:
            raise EthSandboxError("failed to estimate gas")
        tx["gas"] = estimated_gas

    #if "gasPrice" not in tx:
    #    tx["gasPrice"] = 0

    txhash = web3.eth.send_transaction(tx)

    while True:
        try:
            rcpt = web3.eth.get_transaction_receipt(txhash)
            break
        except TransactionNotFound:
            time.sleep(Config.RECEIPT_POLL_INTERVAL)

    if rcpt.status != 1:
        raise EthSandboxError("failed to send transaction", details={"txhash": txhash.hex(), "status": rcpt.status})

    return rcpt


def deploy(web3: Web3, deployer_address: str, constructor_args: List[Any]) -> str:
    setup_compiled = json.loads(Path("/home/ctf/backend/contracts/compiled/Setup.sol/Setup.json").read_text())
    setup_bytecode = setup_compiled["bytecode"]["object"]
    setup_abi = setup_compiled["abi"]
    
    setup_contract = web3.eth.contract(abi=setup_abi, bytecode=setup_bytecode)

    constructor_abi = next((item for item in setup_abi if item.get("type") == "constructor"), None)
    expected_args = constructor_abi.get("inputs", []) if constructor_abi else []
    if len(constructor_args) != len(expected_args):
        raise EthSandboxError(f"constructor expects {len(expected_args)} arguments, but {len(constructor_args)} were provided.")
    
    deploy_tx = {
        "from": deployer_address,
        "value": web3.to_wei(Config.SETUP_CONTRACT_BALANCE, 'ether'),
    }
    constructor_data = setup_contract.constructor(*constructor_args).build_transaction(deploy_tx)
    rcpt = sendTransaction(web3, constructor_data)
    setup_address = rcpt.contractAddress
    return setup_address


def getChallengeAddress(web3: Web3, address):
    abi = json.loads(Path("/home/ctf/backend/contracts/compiled/Setup.sol/Setup.json").read_text())["abi"]
    setupContract = web3.eth.contract(address=address, abi=abi)
    targetAddress = setupContract.functions.TARGET().call()
    return targetAddress


def force_kill_node():
    node_info = get_node_info()
    if not node_info:
        return False
    os.kill(node_info["pid"], signal.SIGTERM)
    return True


def launch_node() -> Dict:
    node_port = str(random.randrange(30000, 60000))
    mnemonic = generate_mnemonic(12, "english")

    with open(Config.ANVIL_LOGFILE, "a") as logfile:
        proc = subprocess.Popen(
            args=[
                "anvil",
                "--accounts", str(Config.N_ACCOUNTS + Config.N_BOTS),
                "--balance", "0",
                "--mnemonic", mnemonic,
                "--port", str(node_port),
                "--block-base-fee-per-gas", "0",
                ],
            stdout=logfile,
            stderr=logfile
            )

    web3 = Web3(Web3.HTTPProvider(f"http://localhost:{node_port}"))
    while True:
        if proc.poll() is not None:
            return None
        if web3.is_connected():
            break
        time.sleep(Config.RECEIPT_POLL_INTERVAL)

    # generate accounts
    deployer_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/0")
    player_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/1")
    deployer_address = deployer_acct.address
    player_address = player_acct.address

    # set balances
    web3.provider.make_request('anvil_setBalance', [deployer_address, hex(Web3.to_wei(Config.DEPLOYER_BALANCE, 'ether'))])
    web3.provider.make_request('anvil_setBalance', [player_address, hex(Web3.to_wei(Config.PLAYER_BALANCE, 'ether'))])
    
    # generate bots
    bots = []
    for acc_index in range(Config.N_ACCOUNTS, Config.N_ACCOUNTS+Config.N_BOTS):
        bot_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/{acc_index}")
        bots.append((bot_acct.address, bot_acct.key.hex()))
        web3.provider.make_request('anvil_setBalance', [bot_acct.address, hex(Web3.to_wei(Config.BOT_BALANCE, 'ether'))])

    # deploy contracts
    setupAddress = deploy(web3, deployer_acct.address, [])
    targetAddress = getChallengeAddress(web3, setupAddress)

    node_info = {
        "port": node_port,
        "pid": proc.pid,
        "logfile": logfile.name,
        "mnemonic": mnemonic,
        "playerPrivateKey": player_acct.key.hex(),
        "playerAddress": player_address,
        "deployerPrivateKey": deployer_acct.key.hex(),
        "deployerAddress": deployer_address,
        "setupAddress": setupAddress,
        "targetAddress": targetAddress,
        "bots": bots,
    }

    with open('/home/ctf/backend/node_info.json', 'w') as f:
        f.write(json.dumps(node_info))

    return node_info

def get_node_info() -> Dict:
    try:
        with open('/home/ctf/backend/node_info.json', 'r') as f:
            node_info = json.loads(f.read())
    except FileNotFoundError:
        return None
    return node_info


def is_solved_checker(web3: Web3) -> bool:
    node_info = get_node_info()
    web3.provider.make_request("anvil_impersonateAccount", [node_info["playerAddress"]])
    result = web3.eth.call({
        "from": node_info["playerAddress"],
        "to": node_info["setupAddress"],
        "data": web3.keccak(text="isSolved()")[:4],
    })
    web3.provider.make_request("anvil_stopImpersonatingAccount", [node_info["playerAddress"]])
    isSolved = int(result.hex(), 16) == 1
    return isSolved


@app.route("/", methods=["GET"])
def index():
    return "rpc is running!"


@app.route("/restart", methods=["GET"])
@cross_origin()
def restart():
    killed = force_kill_node()
    if not killed:
        return "No running node found!", 404
    
    launch_node()

    return "ok", 200


@app.route("/", methods=["POST"])
@cross_origin()
def proxy():
    node_info = get_node_info()
    if not node_info:
        return "No running node found!", 404
    body = request.get_json()
    app.logger.info(f"[*] Incoming JSON-RPC request: {json.dumps(body)}")
    if not body:
        return "invalid content type, only application/json is supported"

    if "id" not in body or "method" not in body or not isinstance(body["method"], str):
        return jsonify(INVALID_REQUEST), 400

    if not any(body["method"].startswith(namespace) for namespace in Config.ALLOWED_NAMESPACES):
        return jsonify(METHOD_NOT_ALLOWED), 403

    if body["method"] == "eth_sendUnsignedTransaction":
        return jsonify(METHOD_NOT_ALLOWED), 403

    # proxy the request to the local node
    resp = requests.post(f"http://localhost:{node_info['port']}", json=body)
    app.logger.info(f"[*] Response from local anvil node: {json.dumps(resp.json())}")
    response = Response(resp.content, resp.status_code, resp.raw.headers.items())
    return response


@app.route("/flag", methods=["GET"])
@cross_origin()
def getFlag():
    node_info = get_node_info()
    if not node_info:
        return "No running node found!", 404
    web3 = Web3(Web3.HTTPProvider(f"http://localhost:{node_info['port']}"))
    if is_solved_checker(web3):
        return Config.FLAG, 200

    return "Conditions not satisfied!", 401


@app.route("/connection_info", methods=["GET"])
@cross_origin()
def connectionInfo():
    node_info = get_node_info()
    if not node_info:
        message = "[*] No running node found. Launching new node..."
        print(message)
        node_info = launch_node()
    else:
        message = "[*] Found node running. Retrieving connection informations..."
        print(message)
    data = {
        "message": message,
        "PlayerPrivateKey": node_info["playerPrivateKey"],
        "PlayerAddress": node_info["playerAddress"],
        "TargetAddress": node_info["targetAddress"],
        "SetupAddress": node_info["setupAddress"],
    }
    return json.dumps(data), 200


if __name__ == "__main__":
    launch_node()
    app.run(host="0.0.0.0", port=Config.LOCAL_RPC_PORT)
