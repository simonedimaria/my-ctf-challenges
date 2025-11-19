#!/usr/bin/env python3
import os, sys, re, time, threading, logging
from selenium import webdriver
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, AnyHttpUrl

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1")
TIMEOUT = int(os.getenv("TIMEOUT", "10"))
EXTENSION_PATH = os.getenv("EXTENSION_PATH", "./ext.zip")
FLAG = os.getenv("FLAG", "space{fake_flag}")

def visit(url: str) -> None:
    try: 
        logger.info(f"bot is visiting {url}")
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

        if not re.fullmatch(r"space\{[a-z0-9_?]+\}", FLAG):
            raise ValueError("Invalid flag format")

        if not os.path.exists(EXTENSION_PATH):
            raise FileNotFoundError(f"Extension not found: {EXTENSION_PATH}")

        opts = webdriver.FirefoxOptions()
        opts.add_argument("-headless")
        opts.set_preference("javascript.options.wasm", False)
        opts.set_preference("javascript.options.baselinejit", False)
        opts.set_preference("javascript.options.ion", False)
        opts.set_preference("javascript.options.asmjs", False)

        driver = webdriver.Firefox(options=opts)
        logger.info("firefox started")

        killer = threading.Timer(TIMEOUT, driver.quit)
        killer.daemon = True
        killer.start()

        try:
            driver.install_addon(EXTENSION_PATH, temporary=True)
            driver.get(f"{BASE_URL}/?flag={FLAG}")
            driver.switch_to.new_window("tab")
            driver.get(url)
            time.sleep(TIMEOUT)
        finally:
            try: killer.cancel()
            except Exception: pass
            try: driver.quit()
            except Exception: pass
            logger.info("firefox closed")
    except Exception as e:
        logger.exception(f"bot error during visit: {e}")

app = FastAPI(port=8001)

class VisitPayload(BaseModel):
    url: AnyHttpUrl

@app.post("/visit")
async def visit_endpoint(payload: VisitPayload, background: BackgroundTasks):
    background.add_task(visit, str(payload.url))
    return {"status": f"bot is visiting {str(payload.url)}"}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python3 bot.py <url>")
    visit(sys.argv[1])