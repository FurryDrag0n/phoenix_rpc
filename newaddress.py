import os

import keychain
from db import get_db_connection
from helpers import (
    build_redeem_script,
    hash160,
    base58check_encode,
    PREFIX_P2SH,
)

RANDOM_SALT_SIZE = 16


def generate_address(
    pubkey_hash: bytes,
    account: str = "",
    deterministic: bool = True,
) -> dict:
    conn = get_db_connection()
    try:
        c = conn.cursor()

        if deterministic:
            master_key = keychain.get_master_key()
            c.execute("BEGIN IMMEDIATE")
            c.execute(
                "SELECT COALESCE(MAX(counter), -1) + 1 FROM wallets "
                "WHERE counter IS NOT NULL"
            )
            counter = c.fetchone()[0]
            salt = keychain.derive_salt(master_key, counter)
        else:
            counter = None
            salt = os.urandom(RANDOM_SALT_SIZE)

        redeem_script = build_redeem_script(salt, pubkey_hash)
        script_hash = hash160(redeem_script)
        address = base58check_encode(script_hash, PREFIX_P2SH)

        c.execute('''
            INSERT INTO wallets
                (counter, salt, redeem_script, script_hash, address, account)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (counter, salt, redeem_script, script_hash, address, account))
        conn.commit()
    finally:
        conn.close()

    return {
        "address": address,
        "counter": counter,
        "salt": salt,
        "redeem_script": redeem_script,
        "script_hash": script_hash,
        "account": account,
    }
