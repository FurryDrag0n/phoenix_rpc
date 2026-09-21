import hashlib
import struct
import time

from db import get_db_connection
from helpers import push_data, varint, SIGHASH_ALL
from kernel_math import (
    check_stake_kernel_hash,
    get_coin_age,
    get_proof_of_stake_reward,
    get_next_target_required_pos,
    compute_tx_offset,
    sha256d,
    nStakeMinAge,
    nModifierInterval,
    CENT,
    COIN,
)
from ecdsa_sign import sign_block_hash
from newaddress import generate_address
from pos_coinstake import build_coinstake, HARDCODED_PUBKEY, p2pk_script, p2sh_script
from pos_block import build_empty_coinbase, build_pos_block, BLOCK_VERSION
from scrypt_hash import scrypt_blockhash

SEARCH_INTERVAL = 60
LOOP_INTERVAL   = 15
MAX_UTXOS       = 100

_FALCON_PUBKEY = None
_FALCON_SECRET = None

def set_falcon_keys(pubkey: bytes, secret: bytes):
    global _FALCON_PUBKEY, _FALCON_SECRET
    _FALCON_PUBKEY = pubkey
    _FALCON_SECRET = secret

def _rpc(rpc_config, method, params=None):
    import requests
    if params is None:
        params = []
    r = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={"jsonrpc": "1.0", "id": "pos", "method": method, "params": params},
        timeout=30,
    )
    res = r.json()
    if res.get("error"):
        raise RuntimeError(f"RPC {method}: {res['error']}")
    return res["result"]

def _get_stakeable_utxos(rpc_config):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute('''
            SELECT txid, vout, redeem_script, amount, block_height
            FROM utxos
            WHERE spent=0 AND block_height IS NOT NULL
            ORDER BY amount DESC
            LIMIT ?
        ''', (MAX_UTXOS,))
        rows = c.fetchall()
    finally:
        conn.close()

    return [
        {
            "txid": r[0],
            "vout": r[1],
            "redeem_script": bytes(r[2]),
            "amount": r[3],
            "block_height": r[4],
        }
        for r in rows
    ]

_MODIFIER_CACHE = {}


def _get_kernel_stake_modifier(rpc_call, kernel_block):
    cache_key = kernel_block["hash"]
    if cache_key in _MODIFIER_CACHE:
        return _MODIFIER_CACHE[cache_key]

    MODIFIER_INTERVAL_RATIO = 3
    def section(s):
        return nModifierInterval * 63 // (63 + (63 - s) * (MODIFIER_INTERVAL_RATIO - 1))
    SELECTION_INTERVAL = sum(section(s) for s in range(64))

    kernel_time = kernel_block["time"]
    target_time = kernel_time + SELECTION_INTERVAL
    mod_time = kernel_time
    current_modifier = int(kernel_block["modifier"], 16)

    cur = kernel_block
    steps = 0
    while mod_time < target_time:
        nxt = cur.get("nextblockhash")
        if not nxt:
            return None
        cur = rpc_call("getblock", [nxt])
        steps += 1
        if steps > 20000:
            return None
        if "stake-modifier" in cur.get("flags", ""):
            mod_time = cur["time"]
            current_modifier = int(cur["modifier"], 16)

    _MODIFIER_CACHE[cache_key] = current_modifier
    return current_modifier

def _find_kernel_solution(rpc_config, utxo, n_bits, now_ts):
    try:
        kernel_tx = _rpc(rpc_config, "getrawtransaction", [utxo["txid"], 1])
    except Exception as e:
        print(f"[POS] getrawtransaction {utxo['txid'][:10]} failed: {e}")
        return None

    block_hash = kernel_tx.get("blockhash")
    if not block_hash:
        print(f"[POS] kernel {utxo['txid'][:10]} has no blockhash (unconfirmed?)")
        return None

    try:
        kernel_block = _rpc(rpc_config, "getblock", [block_hash])
    except Exception as e:
        print(f"[POS] getblock {block_hash[:10]} failed: {e}")
        return None

    n_time_block_from = kernel_block["time"]

    try:
        raw_kernel_hex = _rpc(rpc_config, "getrawtransaction", [utxo["txid"]])
        n_time_tx_prev = struct.unpack_from("<I", bytes.fromhex(raw_kernel_hex), 4)[0]
    except Exception as e:
        print(f"[POS] failed to parse kernel nTime: {e}")
        return None

    n_stake_modifier = _get_kernel_stake_modifier(
        lambda m, p: _rpc(rpc_config, m, p),
        kernel_block,
    )
    if n_stake_modifier is None:
        print(f"[POS] modifier not ready for h={kernel_block['height']} "
              f"(walk reached tip)")
        return None

    kernel_index = None
    vtx_hex = []
    for i, txid in enumerate(kernel_block["tx"]):
        if txid == utxo["txid"]:
            kernel_index = i
        try:
            vtx_hex.append(_rpc(rpc_config, "getrawtransaction", [txid]))
        except Exception:
            vtx_hex.append("")
    if kernel_index is None:
        print(f"[POS] kernel txid not found in block tx list")
        return None
    offset = compute_tx_offset(vtx_hex, kernel_index)

    coinbase_len = len(vtx_hex[0]) // 2 if vtx_hex else 0
    print(f"[POS] kernel params: "
          f"kernel_index={kernel_index} offset={offset} "
          f"nTimeBlockFrom={n_time_block_from} nTimeTxPrev={n_time_tx_prev} "
          f"modifier=0x{n_stake_modifier:016x} kernel_h={kernel_block['height']} "
          f"kernel_block_txs={len(kernel_block['tx'])} "
          f"coinbase_len={coinbase_len} "
          f"nPrevout={utxo['vout']} nValueIn={utxo['amount']}")

    t_max = now_ts
    t_min = max(
        now_ts - SEARCH_INTERVAL,
        n_time_block_from + nStakeMinAge + 1,
        n_time_tx_prev + 1,
    )
    if t_min > t_max:
        print(f"[POS] window empty: t_min={t_min} > t_max={t_max} "
              f"(coin too young)")
        return None

    for n_time_tx in range(t_max, t_min - 1, -1):
        result = check_stake_kernel_hash(
            n_bits=n_bits,
            n_time_block_from=n_time_block_from,
            n_tx_prev_offset=offset,
            n_time_tx_prev=n_time_tx_prev,
            prevout_n=utxo["vout"],
            n_time_tx=n_time_tx,
            n_value_in=utxo["amount"],
            n_stake_modifier=n_stake_modifier,
        )
        if result:
            print(f"[POS] solution: nTimeTx={n_time_tx} "
                  f"hash={result['hash_proof_be'].hex()} "
                  f"target={result['target']:064x} "
                  f"weight={result['weight']} "
                  f"coin_day_weight={result['coin_day_weight']}")
            return {
                "n_time_tx": n_time_tx,
                "result": result,
                "kernel_block": kernel_block,
                "n_time_block_from": n_time_block_from,
            }
    return None

def _submit_block(rpc_config, block_hex: str):
    return _rpc(rpc_config, "submitblock", [block_hex])

def run_pos_miner(rpc_config, interval=LOOP_INTERVAL):
    print("[POS] Miner started")

    if _FALCON_PUBKEY is None or _FALCON_SECRET is None:
        print("[POS] Falcon keys not set, exiting")
        return

    pubkey_hash = hashlib.sha256(_FALCON_PUBKEY).digest()
    rpc_call = lambda m, p: _rpc(rpc_config, m, p)

    while True:
        try:
            info = _rpc(rpc_config, "getinfo")
            height = info["blocks"]
            best_hash = _rpc(rpc_config, "getblockhash", [height])

            n_bits = get_next_target_required_pos(rpc_call, best_hash)
            now_ts = int(time.time())

            utxos = _get_stakeable_utxos(rpc_config)
            if not utxos:
                time.sleep(interval)
                continue

            found = False
            for utxo in utxos:
                coin_age = get_coin_age(
                    rpc_call,
                    [(utxo["txid"], utxo["vout"])],
                    now_ts,
                )
                if coin_age is None or coin_age == 0:
                    continue

                sol = _find_kernel_solution(rpc_config, utxo, n_bits, now_ts)
                if not sol:
                    continue

                print(f"[POS] Found kernel for {utxo['txid'][:10]}:{utxo['vout']} "
                      f"nTimeTx={sol['n_time_tx']} coin_age={coin_age}")

                addr_info = generate_address(pubkey_hash, account="pos")
                with open("wallet_changed.flag", "w") as f:
                    f.write("1")

                cst = build_coinstake(
                    rpc=rpc_call,
                    kernel_utxo=utxo,
                    falcon_pubkey=_FALCON_PUBKEY,
                    falcon_secret=_FALCON_SECRET,
                    falcon_script_hash=addr_info["script_hash"],
                    n_time=sol["n_time_tx"],
                    n_bits=n_bits,
                    f_testnet=True,
                    verbose=True,
                )

                coinbase = build_empty_coinbase(
                    height=height + 1,
                    n_time=sol["n_time_tx"],
                    extra_nonce=1,
                )

                block = build_pos_block(
                    prev_hash=best_hash,
                    height=height + 1,
                    n_bits=n_bits,
                    n_time=sol["n_time_tx"],
                    coinbase_tx=coinbase,
                    coinstake_tx=cst["raw_tx"],
                    scrypt_blockhash_func=scrypt_blockhash,
                    sign_block_func=sign_block_hash,
                )

                print(f"[POS] Submitting block h={height+1} "
                      f"nTimeTx={sol['n_time_tx']} "
                      f"coinstake_txid={cst['txid']} "
                      f"nBits=0x{n_bits:08x} block_size={len(block)}")

                try:
                    res = _submit_block(rpc_config, block.hex())
                    if res is None:
                        print(f"[POS] ✅ Block {height+1} accepted! "
                              f"reward → {addr_info['address']}")
                        found = True
                        break
                    else:
                        print(f"[POS] ❌ Block {height+1} rejected: {res}")
                except Exception as e:
                    print(f"[POS] submitblock error: {e}")

            if not found:
                pass

        except Exception as e:
            print(f"[POS] Loop error: {e}")

        time.sleep(interval)
