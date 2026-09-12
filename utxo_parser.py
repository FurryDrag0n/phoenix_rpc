import os
import time
import requests

from db import get_db_connection
from helpers import ONE_COIN

LAST_KNOWN_FILE = "last_known_block.txt"
LAST_PARSED_FILE = "last_parsed_block.txt"
WALLET_CHANGED_FLAG = "wallet_changed.flag"

INTERVAL = 2

def read_height_file(filename, default=0):
    try:
        with open(filename, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return default

def write_height_file(filename, height):
    with open(filename, "w") as f:
        f.write(str(height))

def rpc_call(rpc_config, method, params=None):
    params = params or []
    resp = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={"jsonrpc": "1.0", "id": method, "method": method, "params": params},
        timeout=15,
    )
    data = resp.json()
    if "result" not in data or data.get("error"):
        raise Exception(f"RPC {method} failed: {data}")
    return data["result"]

def get_info(rpc_config):
    return rpc_call(rpc_config, "getinfo")

def get_block_hash(height, rpc_config):
    return rpc_call(rpc_config, "getblockbynumber", [height])["hash"]

def get_block(block_hash, rpc_config):
    return rpc_call(rpc_config, "getblock", [block_hash])

def get_transaction(txid, rpc_config):
    return rpc_call(rpc_config, "gettransaction", [txid])

def get_mempool_txids(rpc_config):
    return rpc_call(rpc_config, "getrawmempool")

def load_script_map():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT script_hash, redeem_script FROM wallets")
        return {bytes(sh).hex(): bytes(rs) for sh, rs in c.fetchall()}
    finally:
        conn.close()

def process_tx(tx, height, c, script_map):
    for vin in tx.get("vin", []):
        prev_txid = vin.get("txid")
        prev_vout = vin.get("vout")
        if prev_txid is not None and prev_vout is not None:
            c.execute(
                "UPDATE utxos SET spent=1 WHERE txid=? AND vout=?",
                (prev_txid, prev_vout)
            )

    for vout in tx.get("vout", []):
        spk = vout.get("scriptPubKey")
        if not spk:
            continue
        hex_script = spk.get("hex")
        if not hex_script:
            continue
        if hex_script.startswith("a914") and hex_script.endswith("87"):
            script_hash_hex = hex_script[4:-2]
            if script_hash_hex in script_map:
                redeem_script = script_map[script_hash_hex]
                amount_sat = int(vout["value"] * ONE_COIN)
                c.execute('''
                    INSERT INTO utxos (txid, vout, redeem_script, amount, block_height)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(txid, vout) DO UPDATE SET
                        block_height = excluded.block_height
                ''', (tx["txid"], vout["n"], redeem_script, amount_sat, height))

def scan_block(height, rpc_config, script_map):
    print(f"[UTXO] Scanning block {height}...")
    conn = None
    try:
        block = get_block(get_block_hash(height, rpc_config), rpc_config)
        conn = get_db_connection()
        c = conn.cursor()
        for txid in block.get("tx", []):
            tx = get_transaction(txid, rpc_config)
            process_tx(tx, height, c, script_map)
        conn.commit()
        write_height_file(LAST_PARSED_FILE, height)
        print(f"[UTXO] Block {height} processed")
    except Exception as e:
        print(f"[UTXO] ERROR in block {height}: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def scan_mempool(rpc_config, script_map):
    try:
        txids = get_mempool_txids(rpc_config)
    except Exception as e:
        print(f"[MEMPOOL] Failed to get mempool: {e}")
        return

    if not txids:
        return

    print(f"[MEMPOOL] Transactions in mempool: {len(txids)}")
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        for txid in txids:
            try:
                tx = get_transaction(txid, rpc_config)
            except Exception as e:
                print(f"[MEMPOOL] Failed to fetch {txid[:10]}: {e}")
                continue
            process_tx(tx, None, c, script_map)
        conn.commit()
    except Exception as e:
        print(f"[MEMPOOL] Error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def cleanup_orphans(rpc_config):
    print("[ORPHAN] Checking orphan UTXOs...")
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT DISTINCT txid, block_height FROM utxos ORDER BY block_height DESC")
        rows = c.fetchall()
        if not rows:
            print("[ORPHAN] No UTXOs to check")
            return None

        last_valid = None
        deleted_any = False
        max_orphan_height = None

        for txid, height in rows:
            if height is None:
                continue

            try:
                block = get_block(get_block_hash(height, rpc_config), rpc_config)
            except Exception as e:
                print(f"[ORPHAN] Block {height} unreachable ({e}), skipping cleanup")
                return None

            if txid in block.get("tx", []):
                print(f"[ORPHAN] ✓ {txid[:10]} valid in block {height} — stop")
                last_valid = height
                break
            else:
                print(f"[ORPHAN] ✗ {txid[:10]} missing in block {height} — delete")
                c.execute("DELETE FROM utxos WHERE txid=?", (txid,))
                deleted_any = True
                if max_orphan_height is None or height > max_orphan_height:
                    max_orphan_height = height

        conn.commit()

        if not deleted_any:
            print("[ORPHAN] Nothing deleted — no reorg detected")
        else:
            print(f"[ORPHAN] Deleted orphans, max height = {max_orphan_height}")

        return last_valid, deleted_any, max_orphan_height
    finally:
        conn.close()

def run_parser_loop(rpc_config, interval=INTERVAL):
    print("[UTXO] Parser started")

    script_map = load_script_map()
    print(f"[UTXO] Loaded {len(script_map)} addresses")

    result = cleanup_orphans(rpc_config)
    if result is not None:
        last_valid, deleted_any, max_orphan_height = result
        last_parsed = read_height_file(LAST_PARSED_FILE, 0)

        if deleted_any:
            rewind_to = (max_orphan_height - 1) if max_orphan_height is not None else -1
            if rewind_to < last_parsed:
                write_height_file(LAST_PARSED_FILE, rewind_to)
                print(f"[UTXO] Rewound to block {rewind_to} (reorg)")
            else:
                print(f"[UTXO] Orphans deleted but last_parsed={last_parsed} is already lower")
        else:
            print(f"[UTXO] Keep last_parsed={last_parsed}")

    while True:
        try:
            try:
                info = get_info(rpc_config)
            except Exception as e:
                print(f"[UTXO] Daemon unavailable: {e}")
                time.sleep(interval)
                continue

            current_height = info["blocks"]
            write_height_file(LAST_KNOWN_FILE, current_height)

            if os.path.exists(WALLET_CHANGED_FLAG):
                os.remove(WALLET_CHANGED_FLAG)
                script_map = load_script_map()
                print(f"[UTXO] Reloaded {len(script_map)} addresses")

            scan_mempool(rpc_config, script_map)

            last_parsed = read_height_file(LAST_PARSED_FILE, 0)
            if last_parsed < current_height:
                print(f"[UTXO] New blocks: {last_parsed + 1} -> {current_height}")
                for h in range(last_parsed + 1, current_height + 1):
                    scan_block(h, rpc_config, script_map)

        except Exception as e:
            print(f"[UTXO] Loop error: {e}")

        time.sleep(interval)
