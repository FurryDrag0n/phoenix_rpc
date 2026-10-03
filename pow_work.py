import hashlib
import struct
import time
import threading
import requests

from newaddress import generate_address
from helpers import push_data

_jobs = {}
_jobs_lock = threading.Lock()

_current_work = None
_current_work_lock = threading.Lock()

JOB_TTL = 900

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def encode_script_num(n: int) -> bytes:
    if n == 0:
        return b''
    result = bytearray()
    abs_n = abs(n)
    while abs_n:
        result.append(abs_n & 0xff)
        abs_n >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if n < 0 else 0x00)
    elif n < 0:
        result[-1] |= 0x80
    return bytes(result)

def push_script_num(n: int) -> bytes:
    return push_data(encode_script_num(n))

def reverse_4byte_words(data: bytes) -> bytes:
    result = bytearray()
    for i in range(0, len(data), 4):
        result.extend(data[i:i+4][::-1])
    return bytes(result)

def compute_merkle_root(hashes: list) -> bytes:
    if not hashes:
        return b'\x00' * 32
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def build_coinbase(height, coinbasevalue, flags_raw, script_hash,
                   ntime, extra_nonce=1, opreturn_data=b""):
    script_sig = push_script_num(height) + push_script_num(extra_nonce) + flags_raw
    script_pubkey = bytes([0xa9, 0x14]) + script_hash + bytes([0x87])

    n_outputs = 1 + (1 if opreturn_data else 0)

    tx = b""
    tx += struct.pack('<i', 1)
    tx += struct.pack('<I', ntime)
    tx += varint(1)
    tx += b'\x00' * 32
    tx += b'\xff\xff\xff\xff'
    tx += varint(len(script_sig)) + script_sig
    tx += b'\xff\xff\xff\xff'
    tx += varint(n_outputs)

    tx += struct.pack('<q', coinbasevalue)
    tx += varint(len(script_pubkey)) + script_pubkey

    if opreturn_data:
        opret = bytes([0x6a]) + push_data(opreturn_data)
        tx += struct.pack('<q', 0)
        tx += varint(len(opret)) + opret

    tx += struct.pack('<I', 0)
    return tx

def build_getwork_data(header_le: bytes) -> bytes:
    assert len(header_le) == 80
    padded = header_le + b'\x80' + b'\x00' * 39 + struct.pack('>Q', 80 * 8)
    assert len(padded) == 128
    return reverse_4byte_words(padded)

def _get_daemon_height(rpc_config):
    try:
        resp = requests.post(
            rpc_config["url"],
            headers={"Content-Type": "application/json"},
            auth=(rpc_config["user"], rpc_config["password"]),
            json={"jsonrpc": "1.0", "id": "h", "method": "getinfo", "params": []},
            timeout=5,
        )
        return resp.json()["result"]["blocks"]
    except Exception as e:
        print(f"[MINER] getinfo failed: {e}")
        return None

def _get_block_template(rpc_config):
    resp = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={
            "jsonrpc": "1.0", "id": "gbt", "method": "getblocktemplate",
            "params": [{"capabilities": ["coinbasetxn", "workid"]}],
        },
        timeout=15,
    )
    raw = resp.json()
    if raw.get("error") or "result" not in raw:
        raise RuntimeError(f"getblocktemplate failed: {raw}")
    return raw["result"]

def _build_work(rpc_config, pubkey_hash, current_height):
    tpl = _get_block_template(rpc_config)

    print(f"[MINER] Template: height={tpl['height']} bits={tpl['bits']} "
          f"curtime={tpl['curtime']} reward={tpl['coinbasevalue']} "
          f"txs={len(tpl.get('transactions', []))}")

    addr_info = generate_address(pubkey_hash, account="mining")
    script_hash = addr_info["script_hash"]
    address = addr_info["address"]

    with open("wallet_changed.flag", "w") as f:
        f.write("1")

    flags_raw = bytes.fromhex(tpl["coinbaseaux"]["flags"])
    ntime = tpl["curtime"]
    coinbase = build_coinbase(
        height=tpl["height"],
        coinbasevalue=tpl["coinbasevalue"],
        flags_raw=flags_raw,
        script_hash=script_hash,
        ntime=ntime,
        extra_nonce=1,
        opreturn_data=b"phoenix is rising",
    )
    coinbase_hash = sha256d(coinbase)

    transactions = [bytes.fromhex(t["data"]) for t in tpl.get("transactions", [])]
    tx_hashes = [coinbase_hash] + [sha256d(tx) for tx in transactions]
    merkle_root = compute_merkle_root(tx_hashes)

    version_le = struct.pack('<i', tpl["version"])
    prevhash_le = bytes.fromhex(tpl["previousblockhash"])[::-1]
    ntime_le = struct.pack('<I', ntime)
    bits_le = bytes.fromhex(tpl["bits"])[::-1]
    nonce_le = struct.pack('<I', 0)

    header_le = version_le + prevhash_le + merkle_root + ntime_le + bits_le + nonce_le
    assert len(header_le) == 80

    data = build_getwork_data(header_le)

    target_le_hex = bytes.fromhex(tpl["target"])[::-1].hex()

    merkle_hex = merkle_root.hex()
    with _jobs_lock:
        _jobs[merkle_hex] = {
            "version": tpl["version"],
            "prevhash_le": prevhash_le,
            "bits_le": bits_le,
            "coinbase": coinbase,
            "transactions": transactions,
            "height": tpl["height"],
            "address": address,
            "merkle_root": merkle_root,
            "created_at": time.time(),
        }
        cutoff = time.time() - JOB_TTL
        for k in list(_jobs.keys()):
            if _jobs[k]["created_at"] < cutoff:
                del _jobs[k]

    print(f"[MINER] New work: chain_h={current_height} next_h={tpl['height']} "
          f"addr={address} merkle={merkle_hex[:16]}... cb_len={len(coinbase)} "
          f"data={data.hex()[:32]}...")

    return {
        "current_height": current_height,
        "data": data.hex(),
        "target": target_le_hex,
        "midstate": "00" * 32,
        "hash1": "00" * 64,
    }

def handle_getwork_request(rpc_config, pubkey_hash):
    global _current_work

    with _current_work_lock:
        cached = _current_work

    current_height = _get_daemon_height(rpc_config)

    if (cached is not None and current_height is not None
            and cached["current_height"] == current_height):
        return {
            "data": cached["data"],
            "target": cached["target"],
            "midstate": cached["midstate"],
            "hash1": cached["hash1"],
        }

    if current_height is None:
        if cached is not None:
            return {
                "data": cached["data"],
                "target": cached["target"],
                "midstate": cached["midstate"],
                "hash1": cached["hash1"],
            }
        raise RuntimeError("Daemon unreachable and no cached work")

    work = _build_work(rpc_config, pubkey_hash, current_height)
    with _current_work_lock:
        _current_work = work

    return {
        "data": work["data"],
        "target": work["target"],
        "midstate": work["midstate"],
        "hash1": work["hash1"],
    }

def handle_getwork_submit(submitted_data_hex, rpc_config):
    submitted = bytes.fromhex(submitted_data_hex)
    if len(submitted) != 128:
        print(f"[MINER] Invalid data length: {len(submitted)} (expected 128)")
        return False

    data_le = reverse_4byte_words(submitted)

    merkle_hex = data_le[36:68].hex()

    with _jobs_lock:
        job = _jobs.get(merkle_hex)

    if job is None:
        print(f"[MINER] Unknown job: merkle={merkle_hex[:16]}...")
        with _jobs_lock:
            print(f"[MINER] Known: {[k[:16] for k in _jobs.keys()]}")
        return False

    ntime_le = data_le[68:72]
    nonce_le = data_le[76:80]

    header = (
        struct.pack('<i', job["version"]) +
        job["prevhash_le"] +
        job["merkle_root"] +
        ntime_le +
        job["bits_le"] +
        nonce_le
    )
    assert len(header) == 80

    all_txs = [job["coinbase"]] + job["transactions"]
    block = header + varint(len(all_txs))
    for tx in all_txs:
        block += tx
    block += varint(0)  # empty vchBlockSig

    print(f"[MINER] Submitting: h={job['height']} nonce={nonce_le.hex()} "
          f"txs={len(all_txs)} block_len={len(block)}")
    print(f"[MINER] header hex: {header.hex()}")
    print(f"[MINER] coinbase hex: {job['coinbase'].hex()}")

    resp = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={
            "jsonrpc": "1.0", "id": "submit", "method": "submitblock",
            "params": [block.hex()],
        },
        timeout=30,
    )
    raw = resp.json()
    print(f"[MINER] submitblock response: {raw}")

    if raw.get("error"):
        print(f"[MINER] Submit error: {raw['error']}")
        return False

    result = raw.get("result")
    if result is None:
        print(f"[MINER] ✅ Block {job['height']} accepted! Reward → {job['address']}")
        with _jobs_lock:
            _jobs.pop(merkle_hex, None)
        return True

    print(f"[MINER] ❌ Block {job['height']} rejected: {result}")
    return False

def invalidate_work():
    global _current_work
    with _current_work_lock:
        _current_work = None
