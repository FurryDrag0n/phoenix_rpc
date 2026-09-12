import os
import signal
import sys
import threading
import toml
from flask import Flask, request, jsonify, Response
from functools import wraps
import requests

from db import init_db, checkpoint_wal
import keychain
from newaddress import generate_address
from group_tx import handle_listunspent, handle_getbalance
from unlock import handle_sendtoaddress, set_keypair
from utxo_parser import run_parser_loop
import hashlib

try:
    with open("hello.txt", "r", encoding="utf-8") as f:
        print(f.read())
except FileNotFoundError:
    pass

with open("config.toml") as f:
    config = toml.load(f)

DEMON_URL = config["daemon"]["url"]
DEMON_USER = config["daemon"]["user"]
DEMON_PASS = config["daemon"]["password"]

PROXY_HOST = config["proxy"]["host"]
PROXY_PORT = config["proxy"]["port"]

app = Flask(__name__)

pubkey, secret = keychain.get_or_create_keypair()
set_keypair(pubkey, secret)
pubkey_hash = hashlib.sha256(pubkey).digest()
print(f"[KEYCHAIN] Key loaded: pubkey={len(pubkey)}B secret={len(secret)}B")

def check_auth(username, password):
    return username == DEMON_USER and password == DEMON_PASS

def authenticate():
    return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="RPC Proxy"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=['POST'])
@requires_auth
def rpc_proxy():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    method = data.get('method')
    params = data.get('params', [])
    req_id = data.get('id')

    rpc_config = {"url": DEMON_URL, "user": DEMON_USER, "password": DEMON_PASS}

    try:
        if method == 'getnewaddress':
            account = params[0] if params and len(params) > 0 else ""
            print(f"[PROXY] getnewaddress(account='{account}')")
            info = generate_address(pubkey_hash, account)
            with open("wallet_changed.flag", "w") as f:
                f.write("1")
            return jsonify({"result": info["address"], "error": None, "id": req_id})

        if method == 'listunspent':
            return jsonify({
                "result": handle_listunspent(params, rpc_config),
                "error": None, "id": req_id,
            })

        if method == 'getbalance':
            return jsonify({
                "result": handle_getbalance(params, rpc_config),
                "error": None, "id": req_id,
            })

        if method == 'sendtoaddress':
            txid = handle_sendtoaddress(params, rpc_config, broadcast=True)
            return jsonify({"result": txid, "error": None, "id": req_id})

    except Exception as e:
        print(f"[PROXY] {method} error: {e}")
        return jsonify({
            "result": None,
            "error": {"code": -1, "message": str(e)},
            "id": req_id,
        })

    try:
        resp = requests.post(
            DEMON_URL,
            headers={"Content-Type": "application/json"},
            auth=(DEMON_USER, DEMON_PASS),
            json=data,
            timeout=30,
        )
        return Response(resp.text, status=resp.status_code, content_type='application/json')
    except requests.exceptions.RequestException as e:
        print(f"[PROXY] Forward failed: {e}")
        return jsonify({"error": str(e)}), 500

def graceful_shutdown(signum, frame):
    print("\n[MAIN] Signal received, shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

if __name__ == '__main__':
    init_db()
    checkpoint_wal()

    rpc_config = {"url": DEMON_URL, "user": DEMON_USER, "password": DEMON_PASS}
    parser_thread = threading.Thread(
        target=run_parser_loop,
        args=(rpc_config,),
        daemon=True,
    )
    parser_thread.start()

    print(f"[MAIN] Proxy on {PROXY_HOST}:{PROXY_PORT}")
    print(f"[MAIN] Forwarding to {DEMON_URL}")
    app.run(host=PROXY_HOST, port=PROXY_PORT, debug=False, threaded=True)
