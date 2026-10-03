#!/usr/bin/env python3
"""
Трата UTXO с OP_FALCONVERIFY + соль в redeemScript.

Обработчики:
  handle_sendtoaddress(params, rpc_config)      — build + sign + broadcast
  handle_signrawtransaction(params, rpc_config) — только подпись

Общий путь подписи — sign_our_inputs(), используется обоими.
"""

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
    parse_tx,
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

# Оценки размера
SIZE_OVERHEAD = 50
SIZE_PER_INPUT = 1800
SIZE_PER_P2PKH_OUTPUT = 34
SIZE_PER_OPRETURN = 15
SIZE_CHANGE_OUTPUT = 34


# ---------- Кэш ключевой пары ----------

_KEYPAIR = None


def set_keypair(pubkey: bytes, secret: bytes):
    global _KEYPAIR
    _KEYPAIR = (pubkey, secret)


def _get_keypair():
    if _KEYPAIR is None:
        raise RuntimeError("Keypair not set. Call set_keypair().")
    return _KEYPAIR


# ---------- БД ----------

def _get_redeem_script_optional(txid_display: bytes, vout: int):
    """
    txid_display — 32 байта в display-порядке (как в parse_tx).
    Возвращает redeem_script или None.
    """
    txid_hex = txid_display.hex()
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT redeem_script FROM utxos WHERE txid=? AND vout=?",
            (txid_hex, vout),
        )
        row = c.fetchone()
        return bytes(row[0]) if row else None
    finally:
        conn.close()


def _get_redeem_script(txid_hex: str, vout: int):
    """Обязательный вариант — для sendtoaddress, где UTXO уже известны."""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT redeem_script FROM utxos WHERE txid=? AND vout=?",
            (txid_hex, vout),
        )
        row = c.fetchone()
        if not row:
            raise ValueError(f"UTXO {txid_hex}:{vout} not found in DB")
        return bytes(row[0])
    finally:
        conn.close()


def _get_our_addresses():
    """Множество всех наших адресов (для классификации send/consolidate)."""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT address FROM wallets")
        return {row[0] for row in c.fetchall()}
    finally:
        conn.close()


def _mark_spent_and_add_history(
        selected,
        change_txid, change_vout, change_rs, change_amount, change_height,
        txid, amount_net, fee, category, primary_address):
    """
    Помечает выбранные входы потраченными, добавляет change UTXO,
    пишет запись в history.
    """
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

        c.execute('''
            INSERT INTO history
                (txid, category, amount_net, fee, address, block_height, n_time)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            ON CONFLICT(txid) DO UPDATE SET
                category = excluded.category,
                amount_net = excluded.amount_net,
                fee = excluded.fee,
                address = excluded.address,
                n_time = excluded.n_time
        ''', (txid, category, amount_net, fee, primary_address, int(time.time())))

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------- Подпись входов ----------

def sign_our_inputs(inputs, outputs, ntime, locktime=0):
    """
    Подписывает входы, принадлежащие нам (P2SH-Falcon).
    Уже подписанные (непустой scriptSig) не трогает.
    Возвращает (signed_count, unsigned_indexes).
    """
    pubkey, secret = _get_keypair()
    signed = 0
    unsigned = []

    for i, txin in enumerate(inputs):
        if txin['scriptSig']:
            signed += 1
            continue

        rs = _get_redeem_script_optional(txin['txid'], txin['vout'])
        if rs is None:
            unsigned.append(i)
            continue

        sighash = signature_hash(
            1, ntime, inputs, outputs, i, rs, SIGHASH_ALL, locktime
        )

        with oqs.Signature("Falcon-512", secret) as signer:
            falcon_sig = signer.sign(sighash)

        inputs[i]['scriptSig'] = build_script_sig(falcon_sig, pubkey, rs)
        signed += 1

    return signed, unsigned


# ---------- Оценки ----------

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


# ---------- signrawtransaction ----------

def handle_signrawtransaction(params, rpc_config=None):
    """
    signrawtransaction <hex>

    Возвращает dict:
      hex             — подписанная raw hex
      complete        — true если все входы подписаны
      signed_inputs   — сколько входов подписано
      unsigned_inputs — индексы чужих входов
    """
    if not params:
        raise ValueError("signrawtransaction: needs hex param")

    raw = bytes.fromhex(params[0])
    parsed = parse_tx(raw)

    inputs = parsed['vin']
    outputs = parsed['vout']
    ntime = parsed['ntime']
    locktime = parsed['locktime']

    signed, unsigned = sign_our_inputs(inputs, outputs, ntime, locktime)
    signed_raw = serialize_tx(parsed['version'], ntime, inputs, outputs, locktime)
    complete = len(unsigned) == 0

    print(f"[SIGN] inputs={len(inputs)} signed={signed} "
          f"unsigned={len(unsigned)} complete={complete}")

    return {
        "hex": signed_raw.hex(),
        "complete": complete,
        "signed_inputs": signed,
        "unsigned_inputs": unsigned,
    }


# ---------- sendtoaddress ----------

def handle_sendtoaddress(params, rpc_config=None, broadcast=True):
    """
    sendtoaddress <address> <amount> [comment]

    Строит транзакцию, подписывает наши входы, broadcast.
    """
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

    # Оценка комиссии
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

    # Входы
    inputs = []
    for u in selected:
        inputs.append({
            "txid": bytes.fromhex(u["txid"]),
            "vout": u["vout"],
            "scriptSig": b"",
            "sequence": 0xffffffff,
        })

    # Выходы
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

    # Подпись через общий хелпер
    signed, unsigned = sign_our_inputs(inputs, outputs, ntime)
    if unsigned:
        raise RuntimeError(f"Failed to sign inputs: {unsigned}")

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

    # Классификация: send или consolidate
    our_addresses = _get_our_addresses()
    category = "consolidate" if dest_address in our_addresses else "send"
    amount_net = -(amount_sat + fee) if category == "send" else -fee

    change_vout = len(outputs) - 1 if has_change else None
    _mark_spent_and_add_history(
        selected=selected,
        change_txid=txid if has_change else None,
        change_vout=change_vout,
        change_rs=change_rs,
        change_amount=change_sat,
        change_height=None,
        txid=txid,
        amount_net=amount_net,
        fee=fee,
        category=category,
        primary_address=dest_address,
    )
    print(f"[SEND] Marked {len(selected)} inputs spent, "
          f"change {'added' if has_change else 'none'}, "
          f"history: {category} net={amount_net}")

    return data["result"]
