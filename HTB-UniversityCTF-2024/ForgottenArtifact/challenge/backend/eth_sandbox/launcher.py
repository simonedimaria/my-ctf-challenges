# !/usr/bin/env python3
# eth_sandbox/launcher.py

import requests
from dataclasses import dataclass
from typing import Callable, List
from eth_sandbox.config import Config
from eth_sandbox.exceptions import EthSandboxError

RPC_PORT = Config.LOCAL_RPC_PORT
PUBLIC_IP = Config.PUBLIC_IP

@dataclass
class Action:
    name: str
    handler: Callable[[], int]


def new_connection_info_action():
    def action() -> int:
        try:
            req = requests.get(f"http://localhost:{RPC_PORT}/connection_info", timeout=30)
            if req.status_code != 200:
                raise EthSandboxError("Failed to get connection information.")
        except requests.exceptions.RequestException:
            raise EthSandboxError("Request timed out.")
        data = req.json()
        print(data["message"])
        print()
        print(f"Player Private Key : {data['PlayerPrivateKey']}")
        print(f"Player Address     : {data['PlayerAddress']}")
        print(f"Target contract    : {data['TargetAddress']}")
        print(f"Setup contract     : {data['SetupAddress']}")
        return 0

    return Action(name="Get connection informations", handler=action)


def new_restart_instance_action():
    def action() -> int:
        req = requests.get(f"http://localhost:{RPC_PORT}/restart", timeout=30)
        if req.status_code != 200:
            raise EthSandboxError("Restart failed.")
        print("[*] Restart done. Please retrieve the new connection information.")
        return 0

    return Action(name="Restart Instance", handler=action)


def new_get_flag_action():
    def action() -> int:
        req = requests.get(f"http://localhost:{RPC_PORT}/flag", timeout=5)
        if req.status_code != 200:
            print(req.text)
            raise EthSandboxError("Failed to get flag.")
        flag = req.text
        print(flag)
        print()
        return 0

    return Action(name="Get flag", handler=action)


def run_launcher(actions: List[Action]):
    for i, action in enumerate(actions):
        print(f"{i+1} - {action.name}")

    try:
        action_index = int(input("Select action (enter number): ")) - 1
        if action_index < 0 or action_index >= len(actions):
            print("Invalid action selected. Please choose a valid number.")
            exit(1)
        action_status = actions[action_index].handler()
        exit(action_status)
    except ValueError:
        print("Invalid input. Please enter a number.")
    except EthSandboxError as e:
        print(f"Error: {e}")
        print("Ops, something went wrong :(")
        print("Please contact support, will be fixed ASAP.")
        print("Here's a funny cats compilation while you wait: https://youtu.be/DHfRfU3XUEo?si=Ritbs7RaicJp0ZeS")
    except KeyboardInterrupt:
        print("\nExiting.")
        exit(0)
