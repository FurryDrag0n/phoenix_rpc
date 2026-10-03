import hashlib
import oqs

from helpers import (
    push_data,
    serialize_tx,
    signature_hash,
    build_script_sig,
    SIGHASH_ALL,
    ONE_COIN,
)
from kernel_math import get_coin_age, get_proof_of_stake_reward, CENT


# compressed pubkey для privkey=0x1 (secp256k1 G point)
HARDCODED_PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

def p2pk_script(pubkey: bytes) -> bytes:
    return push_data(pubkey) + bytes([0xac])


def p2sh_script(script_hash: bytes) -> bytes:
    return bytes([0xa9, 0x14]) + script_hash + bytes([0x87])

def get_min_fee_coinstake(tx_bytes_len, outputs):
    n_base_fee = CENT
    n_min_fee = (1 + tx_bytes_len // 1000) * n_base_fee

    for amt, script in outputs:
        is_empty = (amt == 0 and len(script) == 0)
        if is_empty:
            continue
        if amt < CENT:
            n_min_fee += n_base_fee

    return n_min_fee

def build_coinstake(
        rpc,
        kernel_utxo: dict,
        falcon_pubkey: bytes,
        falcon_secret: bytes,
        falcon_script_hash: bytes,
        n_time: int,
        n_bits: int,
        verbose: bool = False,
):
    coin_age = get_coin_age(rpc, [(kernel_utxo["txid"], kernel_utxo["vout"])], n_time)
    if coin_age is None:
        raise ValueError("get_coin_age failed")
    if coin_age == 0:
        raise ValueError("coin_age == 0")

    reward = get_proof_of_stake_reward(coin_age, n_bits, n_time)

    if verbose:
        print(f"[coinstake] coin_age={coin_age} ({coin_age/ONE_COIN:.4f} coin-day)")
        print(f"[coinstake] reward  ={reward} ({reward/ONE_COIN:.8f} NVC)")

    inputs = [{
        "txid": bytes.fromhex(kernel_utxo["txid"]),
        "vout": kernel_utxo["vout"],
        "scriptSig": b"",
        "sequence": 0xffffffff,
    }]
    outputs = [
        {"amount": 0, "script": b""},
        {"amount": 0, "script": p2pk_script(HARDCODED_PUBKEY)},
        {"amount": 0, "script": p2sh_script(falcon_script_hash)},
    ]

    min_fee = 4 * CENT
    for it in range(8):
        total_out = kernel_utxo["amount"] + reward - min_fee
        if total_out <= 0:
            raise ValueError(f"total_out <= 0: valueIn={kernel_utxo['amount']} "
                             f"reward={reward} min_fee={min_fee}")
        outputs[2]["amount"] = total_out
        raw = serialize_tx(1, n_time, inputs, outputs)
        new_fee = get_min_fee_coinstake(
            len(raw),
            [(o["amount"], o["script"]) for o in outputs],
        )
        if new_fee == min_fee:
            break
        min_fee = new_fee

    total_out = kernel_utxo["amount"] + reward - min_fee
    outputs[2]["amount"] = total_out

    script_code = kernel_utxo["redeem_script"]
    sighash = signature_hash(1, n_time, inputs, outputs, 0, script_code, SIGHASH_ALL, 0)

    with oqs.Signature("Falcon-512", falcon_secret) as signer:
        falcon_sig = signer.sign(sighash)

    inputs[0]["scriptSig"] = build_script_sig(falcon_sig, falcon_pubkey, script_code)

    raw_final = serialize_tx(1, n_time, inputs, outputs)
    txid = hashlib.sha256(hashlib.sha256(raw_final).digest()).digest()[::-1].hex()

    net_profit = total_out - kernel_utxo["amount"]

    if verbose:
        print(f"[coinstake] min_fee={min_fee} total_out={total_out} "
              f"net={net_profit} ({net_profit/ONE_COIN:.8f} NVC)")
        print(f"[coinstake] txid={txid} size={len(raw_final)} bytes")

    return {
        "raw_tx": raw_final,
        "txid": txid,
        "n_time": n_time,
        "coin_age": coin_age,
        "reward": reward,
        "min_fee": min_fee,
        "total_out": total_out,
        "net_profit": net_profit,
        "outputs": outputs,
    }
