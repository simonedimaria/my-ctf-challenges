import os
import random
import subprocess
import signal
import json
import time
from pathlib import Path
import requests
import markdown
from eth_account.hdaccount import generate_mnemonic
from flask import Flask, Response, redirect, request, render_template, send_file
from flask_cors import CORS, cross_origin
from web3 import Web3

from typing import Any, Callable, Dict, List, Optional, Tuple

from eth_account import Account
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt
from web3 import Web3

Account.enable_unaudited_hdwallet_features()

app = Flask(__name__)
CORS(app)

HTTP_PORT = int(os.getenv("HTTP_PORT", "1337"))

FLAG = os.getenv("FLAG", "HTB{n0th1ng_1s_h1dd3n_1n_th3_bl0ckch41n}")

node_info = dict()


def sendTransaction(web3: Web3, tx: Dict) -> Optional[TxReceipt]:
    if "gas" not in tx:
        tx["gas"] = 10_000_000

    if "gasPrice" not in tx:
        tx["gasPrice"] = 0

    web3.provider.make_request("anvil_impersonateAccount", [tx["from"]])
    txhash = web3.eth.send_transaction(tx)
    web3.provider.make_request("anvil_stopImpersonatingAccount", [tx["from"]])

    while True:
        try:
            rcpt = web3.eth.get_transaction_receipt(txhash)
            break
        except TransactionNotFound:
            time.sleep(0.1)

    if rcpt.status != 1:
        raise Exception("failed to send transaction")

    return rcpt


def deploy(web3: Web3, deployer_address: str) -> str:
    rcpt = sendTransaction(
        web3, {
            "from":
            deployer_address,
            "value":
            Web3.to_wei(1, "ether"),
            "data":
            json.loads(
                Path("/home/ctf/compiled/Setup.sol/Setup.json").read_text())
            ["bytecode"]["object"],
        })

    return rcpt.contractAddress


def getChallengeAddress(web3: Web3, address):
    abi = json.loads(
        Path("/home/ctf/compiled/Setup.sol/Setup.json").read_text())["abi"]
    setupContract = web3.eth.contract(address=address, abi=abi)
    targetAddress = setupContract.functions.TARGET().call()

    return targetAddress


def really_kill_node():
    global node_info
    os.kill(node_info["pid"], signal.SIGTERM)


def launch_node() -> Dict:
    global node_info
    port = random.randrange(30000, 60000)
    # port = 30000
    mnemonic = generate_mnemonic(12, "english")

    proc = subprocess.Popen(
        args=[
            "/root/.foundry/bin/anvil",
            "--accounts",
            "2",  # first account is the deployer, second account is for the user
            "--balance",
            "5000",
            "--mnemonic",
            mnemonic,
            "--port",
            str(port),
            "--block-base-fee-per-gas",
            "0",
        ], )

    web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
    while True:
        if proc.poll() is not None:
            return None
        if web3.is_connected():
            break
        time.sleep(0.1)

    deployer_acct = Account.from_mnemonic(mnemonic,
                                          account_path=f"m/44'/60'/0'/0/0")
    player_acct = Account.from_mnemonic(mnemonic,
                                        account_path=f"m/44'/60'/0'/0/1")

    setupAddress = deploy(web3, deployer_acct.address)
    targetAddress = getChallengeAddress(web3, setupAddress)

    node_info = {
        "port": port,
        "mnemonic": mnemonic,
        "pid": proc.pid,
        "playerPriv": player_acct.key.hex(),
        "playerAddress": player_acct.address,
        "deployer": deployer_acct.key.hex(),
        "deployerAddress": deployer_acct.address,
        "setupAddress": setupAddress,
        "challengeAddress": targetAddress,
    }

    return node_info


@app.route("/")
def index():
    return render_template("home.html")


@app.route("/connection")
def showConnection():
    return render_template("connection.html")


@app.route("/restart", methods=["GET"])
@cross_origin()
def restart():
    really_kill_node()
    node_info = None
    launch_node()
    return {"ok": True}


ALLOWED_NAMESPACES = ["web3", "eth", "net"]


@app.route("/rpc", methods=["POST"])
@cross_origin()
def proxy():
    body = request.get_json()
    if not body:
        return "invalid content type, only application/json is supported"

    if "id" not in body:
        return ""

    if "method" not in body or not isinstance(body["method"], str):
        return {
            "jsonrpc": "2.0",
            "id": body["id"],
            "error": {
                "code": -32600,
                "message": "invalid request",
            },
        }

    ok = (any(body["method"].startswith(namespace)
              for namespace in ALLOWED_NAMESPACES)
          and body["method"] != "eth_sendUnsignedTransaction")
    if not ok:
        return {
            "jsonrpc": "2.0",
            "id": body["id"],
            "error": {
                "code": -32600,
                "message": "invalid request",
            },
        }

    resp = requests.post(f"http://127.0.0.1:{node_info['port']}", json=body)
    response = Response(resp.content, resp.status_code,
                        resp.raw.headers.items())
    return response


def is_solved_checker(web3: Web3, addr: str) -> bool:
    result = web3.eth.call({
        "to": addr,
        "data": web3.keccak(text="isSolved()")[:4],
    })
    return int(result.hex(), 16) == 1


@app.route("/flag", methods=["GET"])
@cross_origin()
def getFlag():
    global node_info

    web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{node_info['port']}"))
    if is_solved_checker(web3, node_info["setupAddress"]):
        restart()
        return FLAG, 200

    return "Conditions not satisfied!", 401


@app.route("/connection_info", methods=["GET"])
@cross_origin()
def connectionInfo():
    global node_info
    d = {
        "PrivateKey": node_info["playerPriv"],
        "Address": node_info["playerAddress"],
        "TargetAddress": node_info["challengeAddress"],
        "setupAddress": node_info["setupAddress"],
    }
    return json.dumps(d), 200

launch_node()
if __name__ == "__main__":
    launch_node()
    app.run(host="0.0.0.0", port=HTTP_PORT)
