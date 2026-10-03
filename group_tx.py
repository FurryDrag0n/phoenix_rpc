from db import get_db_connection
from utxo_parser import read_height_file, LAST_KNOWN_FILE
from helpers import script_hash_to_script_pubkey, ONE_COIN
from kernel_math import nCoinbaseMaturity

MATURITY = nCoinbaseMaturity + 20

def handle_listunspent(params, rpc_config=None):
    minconf = int(params[0]) if len(params) > 0 else 0
    maxconf = int(params[1]) if len(params) > 1 else 9999999

    filter_addresses = None
    if len(params) > 2 and params[2]:
        filter_addresses = set(params[2])

    current_height = read_height_file(LAST_KNOWN_FILE, 0)

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute('''
            SELECT u.txid, u.vout, u.amount, u.block_height,
                   w.script_hash, w.address,
                   h.category
            FROM utxos u
            LEFT JOIN wallets w ON w.redeem_script = u.redeem_script
            LEFT JOIN history h ON h.txid = u.txid
            WHERE u.spent = 0
        ''')
        rows = c.fetchall()
    finally:
        conn.close()

    result = []
    for txid, vout, amount_sat, block_height, script_hash, address, category in rows:
        if block_height is None:
            confirmations = 0
        else:
            confirmations = max(0, current_height - block_height + 1)

        if category in ("mined_pow", "mined_pos"):
            if confirmations < MATURITY:
                continue

        if confirmations < minconf or confirmations > maxconf:
            continue

        if filter_addresses is not None and address not in filter_addresses:
            continue

        spk_hex = script_hash_to_script_pubkey(bytes(script_hash)).hex() if script_hash else ""

        result.append({
            "txid": txid,
            "vout": vout,
            "address": address or "",
            "scriptPubKey": spk_hex,
            "amount": amount_sat / ONE_COIN,
            "confirmations": confirmations,
            "spendable": True,
        })

    return result


def handle_getbalance(params, rpc_config=None):
    account_filter = params[0] if len(params) > 0 and params[0] else None
    minconf = int(params[1]) if len(params) > 1 else 0

    utxos = handle_listunspent([minconf, 9999999, []], rpc_config=rpc_config)

    if account_filter is None:
        total = sum(int(u["amount"] * ONE_COIN) for u in utxos)
        return total / ONE_COIN

    addresses = [u["address"] for u in utxos if u.get("address")]
    if not addresses:
        return 0.0

    conn = get_db_connection()
    try:
        c = conn.cursor()
        placeholders = ",".join("?" * len(addresses))
        c.execute(
            f"SELECT address FROM wallets WHERE account=? AND address IN ({placeholders})",
            [account_filter] + addresses
        )
        allowed = {row[0] for row in c.fetchall()}
    finally:
        conn.close()

    total = sum(
        int(u["amount"] * ONE_COIN)
        for u in utxos
        if u.get("address") in allowed
    )
    return total / ONE_COIN
    
def handle_listtransactions(params, rpc_config=None):
    account = params[0] if len(params) > 0 and params[0] else ""
    count = int(params[1]) if len(params) > 1 else 10
    from_ = int(params[2]) if len(params) > 2 else 0

    if count <= 0:
        count = 10
    if count > 1000:
        count = 1000
    if from_ < 0:
        from_ = 0

    current_height = read_height_file(LAST_KNOWN_FILE, 0)
    maturity = nCoinbaseMaturity + 20

    conn = get_db_connection()
    try:
        c = conn.cursor()
        query = """
            SELECT txid, category, amount_net, fee, address, account,
                   block_height, block_time, n_time
            FROM history
        """
        args = []
        if account:
            query += " WHERE account = ?"
            args.append(account)
        query += " ORDER BY COALESCE(block_time, n_time, created_at) DESC LIMIT ? OFFSET ?"
        args.extend([count, from_])
        c.execute(query, args)
        rows = c.fetchall()
    finally:
        conn.close()

    result = []
    for (txid, category, amount_net, fee, address, acc,
         block_height, block_time, n_time) in rows:

        if block_height is None:
            confirmations = 0
        else:
            confirmations = max(0, current_height - block_height + 1)

        if category in ["mined_pow", "mined_pos"]:
            mapped = "immature" if confirmations < maturity else "generate"
        elif category == "consolidate":
            mapped = "send"
        else:
            mapped = category

        item = {
            "account": acc or "",
            "address": address or "",
            "category": mapped,
            "amount": amount_net / ONE_COIN,
            "fee": fee / ONE_COIN,
            "confirmations": confirmations,
            "txid": txid,
        }
        if block_height is not None:
            item["blockheight"] = block_height
            item["blockindex"] = 1
        if block_time:
            item["blocktime"] = block_time
        item["time"] = n_time or block_time or 0
        item["timereceived"] = n_time or block_time or 0

        result.append(item)

    return result

def select_inputs(target_sat, only_confirmed=False, rpc_config=None):
    raw = handle_listunspent([0, 9999999, []], rpc_config=rpc_config)

    if only_confirmed:
        raw = [u for u in raw if u.get("confirmations", 0) >= 1]

    utxos = sorted(raw, key=lambda u: u["amount"], reverse=True)

    if not utxos:
        return {
            "target": target_sat, "selected": [], "total": 0,
            "remainder": 0, "found": False, "strategy": "empty",
        }

    for u in utxos:
        amount_sat = int(u["amount"] * ONE_COIN)
        if amount_sat == target_sat:
            return {
                "target": target_sat, "selected": [u], "total": amount_sat,
                "remainder": 0, "found": True, "strategy": "exact_single",
            }

    candidates = [u for u in utxos if int(u["amount"] * ONE_COIN) >= target_sat]
    if candidates:
        best = min(candidates, key=lambda u: int(u["amount"] * ONE_COIN))
        total = int(best["amount"] * ONE_COIN)
        return {
            "target": target_sat, "selected": [best], "total": total,
            "remainder": total - target_sat, "found": True, "strategy": "min_single",
        }

    selected = []
    total = 0
    for u in utxos:
        selected.append(u)
        total += int(u["amount"] * ONE_COIN)
        if total >= target_sat:
            break

    return {
        "target": target_sat, "selected": selected, "total": total,
        "remainder": total - target_sat, "found": total >= target_sat,
        "strategy": "greedy_desc",
    }
