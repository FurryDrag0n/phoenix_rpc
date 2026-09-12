import os

from db import get_db_connection
from helpers import (
    build_redeem_script,
    hash160,
    base58check_encode,
    PREFIX_P2SH_TEST,
)

SALT_SIZE = 16
PREFIX_P2SH = PREFIX_P2SH_TEST


def generate_address(pubkey_hash: bytes, account: str = "") -> dict:
    salt = os.urandom(SALT_SIZE)
    redeem_script = build_redeem_script(salt, pubkey_hash)
    script_hash = hash160(redeem_script)
    address = base58check_encode(script_hash, PREFIX_P2SH)

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute('''
            INSERT INTO wallets (salt, redeem_script, script_hash, address, account)
            VALUES (?, ?, ?, ?, ?)
        ''', (salt, redeem_script, script_hash, address, account))
        conn.commit()
    finally:
        conn.close()

    return {
        "address": address,
        "salt": salt,
        "redeem_script": redeem_script,
        "script_hash": script_hash,
        "account": account,
    }
