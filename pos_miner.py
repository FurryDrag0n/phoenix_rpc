import hashlib
import struct
import time
import requests

from db import get_db_connection
from helpers import push_data, varint, SIGHASH_ALL, ONE_COIN
from kernel_math import (
    check_stake_kernel_hash,
    get_coin_age,
    get_proof_of_stake_reward,
    get_next_target_required_pos,
    compute_tx_offset,
    sha256d,
    nStakeMinAge,
    nModifierInterval,
    nCoinbaseMaturity,
    CENT,
    COIN,
    F_TESTNET,
)
from ecdsa_sign import sign_block_hash
from newaddress import generate_address
from pos_coinstake import build_coinstake, HARDCODED_PUBKEY, p2pk_script, p2sh_script
from pos_block import build_empty_coinbase, build_pos_block, BLOCK_VERSION
from scrypt_hash import scrypt_blockhash

SEARCH_INTERVAL = 60
LOOP_INTERVAL   = 15
MAX_UTXOS       = 20

MIN_REWARD = 2 * CENT

MAX_BLOCK_SIZE_GEN = 1_000_000
MAX_EXTRA_TXS = 100

_FALCON_PUBKEY = None
_FALCON_SECRET = None


def set_falcon_keys(pubkey: bytes, secret: bytes):
    global _FALCON_PUBKEY, _FALCON_SECRET
    _FALCON_PUBKEY = pubkey
    _FALCON_SECRET = secret

def _rpc(rpc_config, method, params=None):
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
            SELECT u.txid, u.vout, u.redeem_script, u.amount, u.block_height,
                   h.category
            FROM utxos u
            LEFT JOIN history h ON h.txid = u.txid
            WHERE u.spent=0 AND u.block_height IS NOT NULL
            ORDER BY u.amount DESC
            LIMIT ?
        ''', (MAX_UTXOS,))
        rows = c.fetchall()
    finally:
        conn.close()

    now_height = int(open("last_known_block.txt").read().strip() or "0")
    maturity = nCoinbaseMaturity + 20

    result = []
    for r in rows:
        txid, vout, rs, amount, block_height, category = r
        # Immature mined — не берём
        if category in ("mined_pow", "mined_pos"):
            confirmations = now_height - block_height + 1 if block_height else 0
            if confirmations < maturity:
                continue
        result.append({
            "txid": txid,
            "vout": vout,
            "redeem_script": bytes(rs),
            "amount": amount,
            "block_height": block_height,
        })
    return result

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
        print(f"[POS] kernel {utxo['txid'][:10]} has no blockhash")
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
        print(f"[POS] modifier not ready for h={kernel_block['height']}")
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

    print(f"[POS] kernel params: "
          f"index={kernel_index} offset={offset} "
          f"tbf={n_time_block_from} ttp={n_time_tx_prev} "
          f"modifier=0x{n_stake_modifier:016x} h={kernel_block['height']} "
          f"nPrevout={utxo['vout']} nValueIn={utxo['amount']}")

    t_max = now_ts
    t_min = max(
        now_ts - SEARCH_INTERVAL,
        n_time_block_from + nStakeMinAge + 1,
        n_time_tx_prev + 1,
    )
    if t_min > t_max:
        print(f"[POS] window empty: t_min={t_min} > t_max={t_max}")
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
                  f"weight={result['weight']} cdw={result['coin_day_weight']}")
            return {
                "n_time_tx": n_time_tx,
                "result": result,
                "kernel_block": kernel_block,
                "n_time_block_from": n_time_block_from,
            }
    return None

def _is_final(tx, height, block_time):
    n_lock_time = tx.get("locktime", 0)
    if n_lock_time == 0:
        return True
    if (n_lock_time < 500000000 and n_lock_time < height) or \
       (n_lock_time >= 500000000 and n_lock_time < block_time):
        return True
    for vin in tx.get("vin", []):
        if vin.get("sequence", 0xffffffff) != 0xffffffff:
            return False
    return True

def _collect_extra_txs(rpc_config, n_time, height, kernel_txid, kernel_vout,
                       coinstake_size, coinbase_size):
    try:
        txids = _rpc(rpc_config, "getrawmempool")
    except Exception as e:
        print(f"[POS] getrawmempool failed: {e}")
        return [], 0

    if not txids:
        return [], 0

    budget = MAX_BLOCK_SIZE_GEN - coinstake_size - coinbase_size - 200
    if budget <= 0:
        return [], 0

    extra_txs = []
    total_size = 0
    used_inputs = {(kernel_txid, kernel_vout)}

    for txid in txids:
        if len(extra_txs) >= MAX_EXTRA_TXS:
            break

        try:
            raw_hex = _rpc(rpc_config, "getrawtransaction", [txid])
            tx = _rpc(rpc_config, "getrawtransaction", [txid, 1])
        except Exception:
            continue

        tx_raw = bytes.fromhex(raw_hex)
        tx_size = len(tx_raw)

        if total_size + tx_size > budget:
            continue

        if tx.get("time", 0) > n_time:
            continue

        if not _is_final(tx, height, n_time):
            continue

        conflict = False
        for vin in tx.get("vin", []):
            key = (vin.get("txid"), vin.get("vout"))
            if key in used_inputs:
                conflict = True
                break
        if conflict:
            continue

        new_inputs = [(vin.get("txid"), vin.get("vout")) for vin in tx.get("vin", [])]
        if any(k in used_inputs for k in new_inputs):
            continue
        used_inputs.update(new_inputs)

        extra_txs.append(tx_raw)
        total_size += tx_size

    return extra_txs, total_size

def _submit_block(rpc_config, block_hex):
    return _rpc(rpc_config, "submitblock", [block_hex])

def run_pos_miner(rpc_config, interval=LOOP_INTERVAL):
    print(f"[POS] Miner started (testnet={F_TESTNET}, "
          f"nCoinbaseMaturity={nCoinbaseMaturity}, MIN_REWARD={MIN_REWARD})")

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
                coin_age = get_coin_age(rpc_call, [(utxo["txid"], utxo["vout"])], now_ts)
                if coin_age is None or coin_age == 0:
                    continue

                est_reward = get_proof_of_stake_reward(coin_age, n_bits, now_ts)
                if est_reward < MIN_REWARD:
                    print(f"[POS] skip {utxo['txid'][:10]}:{utxo['vout']} "
                          f"reward={est_reward} < {MIN_REWARD} "
                          f"coin_age={coin_age}")
                    continue

                sol = _find_kernel_solution(rpc_config, utxo, n_bits, now_ts)
                if not sol:
                    continue

                print(f"[POS] Found kernel for {utxo['txid'][:10]}:{utxo['vout']} "
                      f"nTimeTx={sol['n_time_tx']} coin_age={coin_age}")

                addr_info = generate_address(pubkey_hash, account="pos")
                with open("wallet_changed.flag", "w") as f:
                    f.write("1")

                try:
                    cst = build_coinstake(
                        rpc=rpc_call,
                        kernel_utxo=utxo,
                        falcon_pubkey=_FALCON_PUBKEY,
                        falcon_secret=_FALCON_SECRET,
                        falcon_script_hash=addr_info["script_hash"],
                        n_time=sol["n_time_tx"],
                        n_bits=n_bits,
                        verbose=True,
                    )
                except ValueError as e:
                    print(f"[POS] skip kernel: {e}")
                    continue

                coinbase = build_empty_coinbase(
                    height=height + 1,
                    n_time=sol["n_time_tx"],
                    extra_nonce=1,
                )

                extra_txs, extra_size = _collect_extra_txs(
                    rpc_config=rpc_config,
                    n_time=sol["n_time_tx"],
                    height=height + 1,
                    kernel_txid=utxo["txid"],
                    kernel_vout=utxo["vout"],
                    coinstake_size=len(cst["raw_tx"]),
                    coinbase_size=len(coinbase),
                )

                print(f"[POS] extra_txs: {len(extra_txs)} txs, {extra_size} bytes")

                block = build_pos_block(
                    prev_hash=best_hash,
                    height=height + 1,
                    n_bits=n_bits,
                    n_time=sol["n_time_tx"],
                    coinbase_tx=coinbase,
                    coinstake_tx=cst["raw_tx"],
                    scrypt_blockhash_func=scrypt_blockhash,
                    sign_block_func=sign_block_hash,
                    extra_txs=extra_txs,
                )

                print(f"[POS] Submitting h={height+1} "
                      f"nTimeTx={sol['n_time_tx']} "
                      f"coinstake_txid={cst['txid']} "
                      f"nBits=0x{n_bits:08x} "
                      f"block_size={len(block)} "
                      f"txs={2+len(extra_txs)}")

                try:
                    res = _submit_block(rpc_config, block.hex())
                    if res is None:
                        print(f"[POS] Block {height+1} accepted! "
                              f"reward → {addr_info['address']}")
                        found = True
                        break
                    else:
                        print(f"[POS] Block {height+1} rejected: {res}")
                except Exception as e:
                    print(f"[POS] submitblock error: {e}")

            if not found:
                pass

        except Exception as e:
            print(f"[POS] Loop error: {e}")

        time.sleep(interval)
