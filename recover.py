import argparse
import hashlib
import toml

import keychain
from db import get_db_connection, init_db
from helpers import (
    build_redeem_script,
    hash160,
    base58check_encode,
    PREFIX_P2SH,
)
from utxo_parser import (
    get_info,
    get_block_hash,
    get_block,
    get_transaction,
    read_height_file,
    write_height_file,
    LAST_PARSED_FILE,
)


DEFAULT_START_HEIGHT = 1_100_000
DEFAULT_BATCH_SIZE = 20
WALLET_CHANGED_FLAG = "wallet_changed.flag"

def _extract_p2sh_hash(vout):
    spk = vout.get("scriptPubKey") or {}
    hex_script = spk.get("hex", "")
    if not hex_script:
        return None
    if not (hex_script.startswith("a914") and hex_script.endswith("87")):
        return None
    return hex_script[4:-2]


def _build_batch(master_key, pubkey_hash, start, size):
    batch = []
    for i in range(start, start + size):
        salt = keychain.derive_salt(master_key, i)
        rs = build_redeem_script(salt, pubkey_hash)
        sh = hash160(rs)
        addr = base58check_encode(sh, PREFIX_P2SH)
        batch.append((i, salt, rs, sh, addr))
    return batch


def _scan_chain_for_used(rpc_config, start_height, end_height):
    used = set()
    total = end_height - start_height + 1
    if total <= 0:
        return used

    for idx, h in enumerate(range(start_height, end_height + 1), 1):
        if idx == 1 or idx % 2000 == 0 or idx == total:
            pct = idx * 100 // total
            print(f"[RECOVER]   chain {h}/{end_height} ({pct}%) used={len(used)}")

        try:
            block = get_block(get_block_hash(h, rpc_config), rpc_config)
        except Exception as e:
            print(f"[RECOVER]   block {h} skipped: {e}")
            continue

        for txid in block.get("tx", []):
            try:
                tx = get_transaction(txid, rpc_config)
            except Exception:
                continue
            for vout in tx.get("vout", []):
                sh_hex = _extract_p2sh_hash(vout)
                if sh_hex:
                    used.add(sh_hex)

    return used


def _soft_insert(batch, account=""):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("BEGIN IMMEDIATE")
        for counter, salt, rs, sh, addr in batch:
            c.execute('''
                INSERT OR IGNORE INTO wallets
                    (counter, salt, redeem_script, script_hash, address, account)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (counter, salt, rs, sh, addr, account))
        conn.commit()
    finally:
        conn.close()


def _current_max_counter():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT COALESCE(MAX(counter), -1) FROM wallets "
            "WHERE counter IS NOT NULL"
        )
        return c.fetchone()[0]
    finally:
        conn.close()

def recover(rpc_config,
            start_height=DEFAULT_START_HEIGHT,
            account="",
            batch_size=DEFAULT_BATCH_SIZE,
            pubkey_hash=None,
            master_key=None):
    if pubkey_hash is None or master_key is None:
        try:
            master_key = keychain.get_master_key()
        except RuntimeError:
            pub, _ = keychain.get_or_create_keypair()
            if pubkey_hash is None:
                pubkey_hash = hashlib.sha256(pub).digest()
            master_key = keychain.get_master_key()
        else:
            if pubkey_hash is None:
                # мастер-ключ есть, но pubkey_hash не дан - без него нельзя
                pub, _ = keychain.get_or_create_keypair()
                pubkey_hash = hashlib.sha256(pub).digest()

    tip = get_info(rpc_config)["blocks"]
    if start_height > tip:
        print(f"[RECOVER] start_height={start_height} > tip={tip}, nothing to scan")
        return 0

    print(f"[RECOVER] Scanning chain [{start_height}..{tip}] for our addresses...")
    used = _scan_chain_for_used(rpc_config, start_height, tip)
    print(f"[RECOVER] Chain scan done. Unique P2SH hashes: {len(used)}")

    counter = _current_max_counter() + 1
    print(f"[RECOVER] Generating batches from counter={counter}, size={batch_size}")

    saved_total = 0
    while True:
        batch = _build_batch(master_key, pubkey_hash, counter, batch_size)
        hashes = {sh.hex() for _, _, _, sh, _ in batch}
        hits = hashes & used

        if not hits:
            print(f"[RECOVER] Batch [{counter}..{counter + batch_size - 1}] empty — stop")
            break

        _soft_insert(batch, account)
        saved_total += len(batch)
        print(f"[RECOVER] Batch [{counter}..{counter + batch_size - 1}] saved "
              f"({len(hits)} hits)")
        counter += batch_size

    if saved_total == 0:
        print("[RECOVER] Nothing recovered")
        return 0

    last_parsed = read_height_file(LAST_PARSED_FILE, 0)
    if last_parsed > start_height:
        write_height_file(LAST_PARSED_FILE, start_height)
        print(f"[RECOVER] Rewound last_parsed_block: {last_parsed} -> {start_height}")
    else:
        print(f"[RECOVER] last_parsed_block={last_parsed} already <= {start_height}")

    with open(WALLET_CHANGED_FLAG, "w") as f:
        f.write("1")

    print(f"[RECOVER] Done. Saved {saved_total} addresses.")
    return saved_total

def main():
    parser = argparse.ArgumentParser(description="Recover wallet addresses")
    parser.add_argument("--start-height", type=int, default=DEFAULT_START_HEIGHT,
                        help=f"Start height ({DEFAULT_START_HEIGHT} by default)")
    parser.add_argument("--account", default="")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()

    with open("config.toml") as f:
        config = toml.load(f)
    rpc_config = {
        "url": config["daemon"]["url"],
        "user": config["daemon"]["user"],
        "password": config["daemon"]["password"],
    }

    init_db()
    recover(
        rpc_config,
        start_height=args.start_height,
        account=args.account,
        batch_size=args.batch,
    )


if __name__ == "__main__":
    main()
