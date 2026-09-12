import time
import toml
import hashlib
import oqs
import requests

from db import get_db_connection
from group_tx import select_inputs
from newaddress import generate_address
from helpers import (
    address_to_output_script,
    build_opreturn,
    build_script_sig,
    compute_txid,
    serialize_tx,
    signature_hash,
    ONE_COIN,
    SIGHASH_ALL,
    MAX_OPRETURN_BYTES,
)

with open("config.toml") as f:
    config = toml.load(f)

SAT_PER_BYTE = config["wallet"]["sat_per_byte"]
DUST_THRESHOLD = config["wallet"]["dust_threshold"]

SIZE_OVERHEAD = 50
SIZE_PER_INPUT = 1800
SIZE_PER_P2PKH_OUTPUT = 34
SIZE_PER_OPRETURN = 15
SIZE_CHANGE_OUTPUT = 34

_KEYPAIR = None

def set_keypair(pubkey: bytes, secret: bytes):
    global _KEYPAIR
    _KEYPAIR = (pubkey, secret)

def _get_keypair():
    if _KEYPAIR is None:
        raise RuntimeError("Keypair not set. Call set_keypair().")
    return _KEYPAIR

def estimate_tx_size(n_in, n_p2pkh_out, n_opreturn, has_change):
    size = SIZE_OVERHEAD
    size += n_in * SIZE_PER_INPUT
    size += n_p2pkh_out * SIZE_PER_P2PKH_OUTPUT
    size += n_opreturn * SIZE_PER_OPRETURN
    if has_change:
        size += SIZE_CHANGE_OUTPUT
    return size

def compute_fee(size_bytes):
    return SAT_PER_BYTE * size_bytes

def _get_redeem_script(txid, vout):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT redeem_script FROM utxos WHERE txid=? AND vout=?", (txid, vout))
        row = c.fetchone()
        if not row:
            raise ValueError(f"UTXO {txid}:{vout} not found in DB")
        return bytes(row[0])
    finally:
        conn.close()

def _mark_spent_and_add_change(selected, change_txid, change_vout, change_rs, change_amount, change_height=None):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        for u in selected:
            c.execute(
                "UPDATE utxos SET spent=1 WHERE txid=? AND vout=?",
                (u["txid"], u["vout"])
            )
        if change_txid is not None:
            c.execute('''
                INSERT INTO utxos (txid, vout, redeem_script, amount, block_height)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    block_height = excluded.block_height
            ''', (change_txid, change_vout, change_rs, change_amount, change_height))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def handle_sendtoaddress(params, rpc_config=None, broadcast=True):
    if len(params) < 2:
        raise ValueError("sendtoaddress: needs at least 2 params (address, amount)")

    dest_address = params[0]
    amount_nvc = float(params[1])
    comment = params[2] if len(params) > 2 else ""

    if amount_nvc <= 0:
        raise ValueError("amount must be > 0")

    pubkey, secret = _get_keypair()
    pubkey_hash = hashlib.sha256(pubkey).digest()

    amount_sat = int(round(amount_nvc * ONE_COIN))
    has_comment = bool(comment)
    if has_comment:
        cb = comment.encode("utf-8")
        if len(cb) > MAX_OPRETURN_BYTES:
            raise ValueError(f"comment too long (max {MAX_OPRETURN_BYTES} bytes)")

    # Первый проход: оценка
    fee_guess = compute_fee(estimate_tx_size(1, 1, 1 if has_comment else 0, True))
    target_guess = amount_sat + fee_guess

    result = select_inputs(target_guess, only_confirmed=False)
    if not result["found"]:
        raise ValueError(
            f"Insufficient funds: need ≥{target_guess}, available {result['total']}"
        )

    selected = result["selected"]
    total_in = result["total"]
    n_in = len(selected)

    size_with_change = estimate_tx_size(n_in, 1, 1 if has_comment else 0, True)
    fee = compute_fee(size_with_change)

    if total_in < amount_sat + fee:
        target_retry = amount_sat + fee + DUST_THRESHOLD
        result = select_inputs(target_retry, only_confirmed=False)
        if not result["found"]:
            raise ValueError(
                f"Insufficient funds: need ≥{amount_sat + fee}, available {total_in}"
            )
        selected = result["selected"]
        total_in = result["total"]
        n_in = len(selected)
        size_with_change = estimate_tx_size(n_in, 1, 1 if has_comment else 0, True)
        fee = compute_fee(size_with_change)
        if total_in < amount_sat + fee:
            raise ValueError(f"Insufficient funds even with {n_in} inputs")

    change_sat = total_in - amount_sat - fee
    has_change = change_sat >= DUST_THRESHOLD

    change_address = None
    change_rs = None
    if has_change:
        addr_info = generate_address(pubkey_hash, account="change")
        change_address = addr_info["address"]
        change_rs = addr_info["redeem_script"]

        with open("wallet_changed.flag", "w") as f:
            f.write("1")
    else:
        fee += change_sat
        change_sat = 0

    inputs = []
    redeem_scripts = []
    for u in selected:
        rs = _get_redeem_script(u["txid"], u["vout"])
        redeem_scripts.append(rs)
        inputs.append({
            "txid": bytes.fromhex(u["txid"]),
            "vout": u["vout"],
            "scriptSig": b"",
            "sequence": 0xffffffff,
        })

    outputs = [{
        "amount": amount_sat,
        "script": address_to_output_script(dest_address),
    }]
    if has_comment:
        outputs.append({
            "amount": 0,
            "script": build_opreturn(comment.encode("utf-8")),
        })
    if has_change:
        outputs.append({
            "amount": change_sat,
            "script": address_to_output_script(change_address),
        })

    ntime = int(time.time())

    for i in range(len(inputs)):
        script_code = redeem_scripts[i]
        sighash = signature_hash(1, ntime, inputs, outputs, i, script_code, SIGHASH_ALL)
        with oqs.Signature("Falcon-512", secret) as signer:
            signature = signer.sign(sighash)
        inputs[i]["scriptSig"] = build_script_sig(signature, pubkey, script_code)

    raw_tx = serialize_tx(1, ntime, inputs, outputs)
    raw_hex = raw_tx.hex()
    txid = compute_txid(raw_tx)

    print(f"[SEND] txid={txid[:10]} inputs={n_in} amount={amount_sat} "
          f"fee={fee} change={change_sat} est={size_with_change}B real={len(raw_tx)}B")

    if not broadcast:
        return raw_hex

    if rpc_config is None:
        raise ValueError("rpc_config required for broadcast")

    resp = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={"jsonrpc": "1.0", "id": "broadcast", "method": "sendrawtransaction",
              "params": [raw_hex]},
        timeout=30,
    )
    data = resp.json()
    if data.get("error") or "result" not in data:
        raise RuntimeError(f"Broadcast failed: {data}")

    change_vout = len(outputs) - 1 if has_change else None
    _mark_spent_and_add_change(
        selected=selected,
        change_txid=txid if has_change else None,
        change_vout=change_vout,
        change_rs=change_rs,
        change_amount=change_sat,
        change_height=None,
    )
    print(f"[SEND] Marked {len(selected)} inputs spent, change {'added' if has_change else 'none'}")

    return data["result"]
