import os
import struct
import threading
import time
import hashlib
import requests
import oqs

from db import get_db_connection
from helpers import (
    hash160, base58check_encode, PREFIX_P2SH,
    parse_tx, serialize_tx, signature_hash, build_script_sig,
    SIGHASH_ALL,
)
from newaddress import generate_address
from kernel_math import nCoinbaseMaturity


ANCHOR_VALUE = 1
DEFAULT_CHUNK = 10_000
MAX_SCRIPT_ELEMENT = 10_000
MAX_TX_SIZE = 995_000
MAX_ZERO_OUTPUTS = 99
SCRIPTSIG_ESTIMATE = 1_700


_pstore_lock = threading.Lock()
_pubkey = None
_secret = None


def set_keys(pubkey: bytes, secret: bytes):
    global _pubkey, _secret
    _pubkey = pubkey
    _secret = secret

def _rpc(rpc_config, method, params=None):
    if params is None:
        params = []
    r = requests.post(
        rpc_config["url"],
        headers={"Content-Type": "application/json"},
        auth=(rpc_config["user"], rpc_config["password"]),
        json={"jsonrpc": "1.0", "id": "pstore",
              "method": method, "params": params},
        timeout=30,
    )
    res = r.json()
    if res.get("error"):
        raise RuntimeError(f"RPC {method}: {res['error']}")
    return res["result"]


def _load_source(src: str) -> bytes:
    if src.startswith(("http://", "https://")):
        r = requests.get(src, timeout=60)
        r.raise_for_status()
        return r.content
    with open(src, "rb") as f:
        return f.read()


def _get_chain_height(rpc_config):
    try:
        return int(_rpc(rpc_config, "getinfo")["blocks"])
    except Exception as e:
        print(f"[PSTORE] getinfo failed: {e}, falling back to file")
        try:
            return int(open("last_known_block.txt").read().strip() or "0")
        except Exception:
            return 0

def _varint(i):
    if i < 0xFD: return struct.pack("<B", i)
    if i <= 0xFFFF: return b"\xfd" + struct.pack("<H", i)
    if i <= 0xFFFFFFFF: return b"\xfe" + struct.pack("<I", i)
    return b"\xff" + struct.pack("<Q", i)


def _varint_len(i):
    if i < 0xFD: return 1
    if i <= 0xFFFF: return 3
    if i <= 0xFFFFFFFF: return 5
    return 9


def _build_opreturn(data: bytes) -> bytes:
    if len(data) > MAX_SCRIPT_ELEMENT:
        raise ValueError(f"chunk {len(data)} > {MAX_SCRIPT_ELEMENT}")
    s = b"\x6a"
    if len(data) <= 75:
        s += struct.pack("<B", len(data))
    elif len(data) <= 0xFF:
        s += b"\x4c" + struct.pack("<B", len(data))
    elif len(data) <= 0xFFFF:
        s += b"\x4d" + struct.pack("<H", len(data))
    else:
        s += b"\x4e" + struct.pack("<I", len(data))
    return s + data


def _p2sh_spk(redeem_script: bytes) -> bytes:
    return b"\xa9\x14" + hash160(redeem_script) + b"\x87"


def _redeem_to_address(redeem_script: bytes) -> str:
    return base58check_encode(hash160(redeem_script), PREFIX_P2SH)


def _estimate_tx_size(zero_outputs: int, anchor_spk_len: int = 23) -> int:
    size = 4 + 4
    size += _varint_len(1)
    size += 32 + 4
    size += _varint_len(SCRIPTSIG_ESTIMATE) + SCRIPTSIG_ESTIMATE
    size += 4
    size += _varint_len(1 + zero_outputs)
    size += 8 + _varint_len(anchor_spk_len) + anchor_spk_len
    for _ in range(zero_outputs):
        size += 8 + 3 + (3 + MAX_SCRIPT_ELEMENT)
    size += 4
    return size


def _make_pstore_raw(prev_txid, prev_vout, anchor_spk, zero_scripts, n_time):
    tx = struct.pack("<I", 1) + struct.pack("<I", n_time)
    tx += _varint(1)
    tx += bytes.fromhex(prev_txid)[::-1] + struct.pack("<I", prev_vout)
    tx += _varint(0)
    tx += struct.pack("<I", 0xFFFFFFFF)
    tx += _varint(1 + len(zero_scripts))
    tx += struct.pack("<Q", ANCHOR_VALUE)
    tx += _varint(len(anchor_spk)) + anchor_spk
    for s in zero_scripts:
        tx += struct.pack("<Q", 0)
        tx += _varint(len(s)) + s
    tx += struct.pack("<I", 0)
    return tx.hex()


def _make_split_raw(txid_in, vout_in, anchor_spk, change_spk,
                    change_amount, n_time):
    tx = struct.pack("<I", 1) + struct.pack("<I", n_time)
    tx += _varint(1)
    tx += bytes.fromhex(txid_in)[::-1] + struct.pack("<I", vout_in)
    tx += _varint(0)
    tx += struct.pack("<I", 0xFFFFFFFF)
    tx += _varint(2)
    tx += struct.pack("<Q", ANCHOR_VALUE)
    tx += _varint(len(anchor_spk)) + anchor_spk
    tx += struct.pack("<Q", change_amount)
    tx += _varint(len(change_spk)) + change_spk
    tx += struct.pack("<I", 0)
    return tx.hex()

def _sign_pstore_tx(raw_hex, redeem_script):
    if _pubkey is None or _secret is None:
        raise RuntimeError("pstore: keys not set (call set_keys)")

    raw = bytes.fromhex(raw_hex)
    parsed = parse_tx(raw)
    inputs = parsed["vin"]
    outputs = parsed["vout"]
    ntime = parsed["ntime"]
    locktime = parsed["locktime"]

    if len(inputs) != 1:
        raise RuntimeError(f"pstore: expected 1 input, got {len(inputs)}")

    sighash = signature_hash(
        1, ntime, inputs, outputs, 0,
        redeem_script, SIGHASH_ALL, locktime,
    )
    with oqs.Signature("Falcon-512", _secret) as signer:
        falcon_sig = signer.sign(sighash)

    inputs[0]["scriptSig"] = build_script_sig(falcon_sig, _pubkey, redeem_script)
    signed_raw = serialize_tx(parsed["version"], ntime, inputs, outputs, locktime)
    return signed_raw.hex()


def _decode_txid(hex_tx, rpc_config):
    return _rpc(rpc_config, "decoderawtransaction", [hex_tx])["txid"]


def _read_anchor(c):
    c.execute("SELECT txid, vout, redeem_script, address, confirmed "
              "FROM pstore_anchor WHERE id=1")
    row = c.fetchone()
    if not row or row[0] is None:
        return None
    return {
        "txid": row[0], "vout": row[1],
        "redeem_script": bytes(row[2]),
        "address": row[3], "confirmed": row[4],
    }


def _write_anchor(c, txid, vout, redeem_script, address, confirmed):
    c.execute('''
        UPDATE pstore_anchor
        SET txid=?, vout=?, redeem_script=?, address=?, confirmed=?,
            updated_at=strftime('%s','now')
        WHERE id=1
    ''', (txid, vout, redeem_script, address, 1 if confirmed else 0))


def _validate_anchor(c, anchor):
    if anchor is None:
        return None

    txid, vout = anchor["txid"], anchor["vout"]

    c.execute("SELECT 1 FROM priority_txs WHERE txid=?", (txid,))
    if c.fetchone():
        # Pending.
        if anchor["confirmed"]:
            # Устаревший флаг — починим.
            anchor["confirmed"] = 0
            c.execute("UPDATE pstore_anchor SET confirmed=0 WHERE id=1")
        return anchor

    c.execute("SELECT spent FROM utxos WHERE txid=? AND vout=?", (txid, vout))
    r = c.fetchone()
    if r and r[0] == 0:
        # Подтверждён, 1-sat на месте.
        if not anchor["confirmed"]:
            anchor["confirmed"] = 1
            c.execute("UPDATE pstore_anchor SET confirmed=1 WHERE id=1")
        return anchor

    print(f"[PSTORE] anchor {txid[:12]}:{vout} invalid — resetting")
    c.execute('''UPDATE pstore_anchor
                 SET txid=NULL, vout=NULL, redeem_script=NULL,
                     address=NULL, confirmed=0,
                     updated_at=strftime('%s','now')
                 WHERE id=1''')
    return None


def _try_adopt_existing_anchor(c):
    c.execute('''
        SELECT u.txid, u.vout, u.redeem_script, u.amount, u.block_height
        FROM utxos u
        WHERE u.spent=0
          AND u.amount = ?
          AND u.block_height IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM priority_txs p
              WHERE p.prev_txid = u.txid AND p.prev_vout = u.vout
          )
        ORDER BY u.block_height DESC
        LIMIT 1
    ''', (ANCHOR_VALUE,))
    row = c.fetchone()
    if not row:
        return None
    txid, vout, rs, _amount, _height = row
    rs = bytes(rs)
    return {
        "txid": txid,
        "vout": vout,
        "redeem_script": rs,
        "address": _redeem_to_address(rs),
        "confirmed": 1,
    }

def _pick_split_utxo(c, rpc_config):
    c.execute('''
        SELECT u.txid, u.vout, u.redeem_script, u.amount, u.block_height,
               h.category
        FROM utxos u
        LEFT JOIN history h ON h.txid = u.txid
        WHERE u.spent=0
          AND u.block_height IS NOT NULL
          AND u.amount > ?
          AND NOT EXISTS (
              SELECT 1 FROM priority_txs p
              WHERE p.prev_txid = u.txid AND p.prev_vout = u.vout
          )
        ORDER BY u.block_height DESC, u.amount ASC
        LIMIT 50
    ''', (ANCHOR_VALUE + 1000,))
    rows = c.fetchall()

    if not rows:
        c.execute("SELECT COUNT(*), "
                  "SUM(CASE WHEN spent=0 THEN 1 ELSE 0 END), "
                  "SUM(CASE WHEN spent=0 AND block_height IS NOT NULL "
                  "THEN 1 ELSE 0 END), "
                  "SUM(CASE WHEN spent=0 AND block_height IS NOT NULL "
                  "AND amount > ? THEN 1 ELSE 0 END) "
                  "FROM utxos", (ANCHOR_VALUE + 1000,))
        total, unspent, confirmed, eligible = c.fetchone()
        print(f"[PSTORE] utxos total={total} unspent={unspent} "
              f"confirmed={confirmed} amount_ok={eligible}")
        return None

    now_height = _get_chain_height(rpc_config)
    maturity = nCoinbaseMaturity + 20
    print(f"[PSTORE] pick_split: now_height={now_height} "
          f"maturity={maturity} candidates={len(rows)}")

    for row in rows:
        txid, vout, rs, amount, height, category = row
        if category in ("mined_pow", "mined_pos"):
            conf = now_height - height + 1 if height else 0
            if conf < maturity:
                print(f"[PSTORE]   skip {txid[:12]}:{vout} "
                      f"amount={amount} — immature {category} "
                      f"(conf {conf} < {maturity})")
                continue
        print(f"[PSTORE]   pick {txid[:12]}:{vout} amount={amount} "
              f"height={height} category={category}")
        return row

    print(f"[PSTORE]   no candidate passed filters")
    return None


def _build_split(rpc_config, change_pubkey_hash, n_time):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        row = _pick_split_utxo(c, rpc_config)
    finally:
        conn.close()

    if row is None:
        return None, None

    txid_in, vout_in, rs_in, amount_in, _height, _category = row
    rs_in = bytes(rs_in)

    anchor_spk = _p2sh_spk(rs_in)
    anchor_address = _redeem_to_address(rs_in)

    change_info = generate_address(change_pubkey_hash, account="pstore-change")
    change_spk = _p2sh_spk(change_info["redeem_script"])
    change_amount = amount_in - ANCHOR_VALUE

    raw = _make_split_raw(txid_in, vout_in, anchor_spk, change_spk,
                          change_amount, n_time)
    signed = _sign_pstore_tx(raw, rs_in)
    txid = _decode_txid(signed, rpc_config)

    print(f"[PSTORE] split {txid[:12]} input={txid_in[:12]}:{vout_in} "
          f"amount={amount_in} change={change_amount}")

    tx_dict = {
        "txid": txid,
        "raw": bytes.fromhex(signed),
        "kind": "split", "seq": 0,
        "prev_txid": txid_in, "prev_vout": vout_in,
    }
    new_anchor = {
        "txid": txid, "vout": 0,
        "redeem_script": rs_in,
        "address": anchor_address,
    }
    return tx_dict, new_anchor

def _group_chunks(chunks_rev):
    groups, cur = [], []
    for chunk in chunks_rev:
        test = cur + [chunk]
        n_conservative = len(test) + 2
        if (n_conservative <= MAX_ZERO_OUTPUTS
                and _estimate_tx_size(n_conservative) <= MAX_TX_SIZE):
            cur.append(chunk)
        else:
            if cur:
                groups.append(cur)
            cur = [chunk]
    if cur:
        groups.append(cur)
    return groups


def _build_file_chain(data, anchor, rpc_config, n_time):
    chunks = [data[i:i+DEFAULT_CHUNK] for i in range(0, len(data), DEFAULT_CHUNK)]
    chunks_rev = chunks[::-1]
    if not chunks_rev:
        raise ValueError("empty file")

    groups = _group_chunks(chunks_rev)
    n_groups = len(groups)
    anchor_spk = _p2sh_spk(anchor["redeem_script"])

    txs = []
    prev_txid = anchor["txid"]
    prev_vout = anchor["vout"]

    for gi, group in enumerate(groups):
        is_first = (gi == 0)
        is_last = (gi == n_groups - 1)

        zero_scripts = []
        if is_first:
            zero_scripts.append(b"\x00")
        for chunk in reversed(group):
            zero_scripts.append(_build_opreturn(chunk))
        if is_last:
            zero_scripts.append(b"\x00")

        if len(zero_scripts) > MAX_ZERO_OUTPUTS:
            raise RuntimeError(
                f"pstore: {len(zero_scripts)} zero-outputs > {MAX_ZERO_OUTPUTS}"
            )

        raw = _make_pstore_raw(prev_txid, prev_vout, anchor_spk,
                               zero_scripts, n_time)
        signed = _sign_pstore_tx(raw, anchor["redeem_script"])
        txid = _decode_txid(signed, rpc_config)

        txs.append({
            "txid": txid,
            "raw": bytes.fromhex(signed),
            "kind": "pstore",
            "seq": gi,
            "prev_txid": prev_txid,
            "prev_vout": prev_vout,
        })
        prev_txid = txid
        prev_vout = 0

    return txs

def handle_pstore(params, rpc_config):
    if not params:
        raise ValueError("pstore: file path or URL required")
    src = params[0]
    comment = params[1] if len(params) > 1 else os.path.basename(src)

    if _pubkey is None or _secret is None:
        raise RuntimeError("pstore: keys not set (call set_keys)")

    pubkey_hash = hashlib.sha256(_pubkey).digest()
    data = _load_source(src)
    print(f"[PSTORE] source={src} size={len(data)}B")

    n_time = int(time.time())

    with _pstore_lock:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            anchor = _read_anchor(c)
            anchor = _validate_anchor(c, anchor)

            if anchor is None:
                adopted = _try_adopt_existing_anchor(c)
                if adopted is not None:
                    print(f"[PSTORE] adopted existing 1-sat as anchor: "
                          f"{adopted['txid'][:12]}:{adopted['vout']}")
                    _write_anchor(c, adopted["txid"], adopted["vout"],
                                  adopted["redeem_script"],
                                  adopted["address"], 1)
                    anchor = adopted
            conn.commit()
        finally:
            conn.close()

        to_store = []
        split_txid = None

        if anchor is None:
            print("[PSTORE] no anchor — building split")
            split_tx, anchor = _build_split(rpc_config, pubkey_hash, n_time)
            if split_tx is None:
                raise RuntimeError("no suitable UTXO to split")
            split_txid = split_tx["txid"]
            to_store.append(split_tx)

        chain = _build_file_chain(data, anchor, rpc_config, n_time)
        file_id = chain[-1]["txid"]

        base_seq = len(to_store)
        for i, t in enumerate(chain):
            t["seq"] = base_seq + i
        to_store.extend(chain)

        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("BEGIN IMMEDIATE")
            try:
                for t in to_store:
                    c.execute('''
                        INSERT OR REPLACE INTO priority_txs
                            (txid, chain_id, kind, seq, raw,
                             prev_txid, prev_vout, size, n_time, comment)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (t["txid"], file_id, t["kind"], t["seq"], t["raw"],
                          t.get("prev_txid"), t.get("prev_vout"),
                          len(t["raw"]), n_time, comment))

                _write_anchor(
                    c,
                    txid=file_id, vout=0,
                    redeem_script=anchor["redeem_script"],
                    address=anchor["address"],
                    confirmed=0,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()

    print(f"[PSTORE] queued file_id={file_id[:12]} "
          f"txs={len(chain)} split={split_txid is not None} n_time={n_time}")

    return {
        "file_id": file_id,
        "tx_count": len(chain),
        "size": sum(len(t["raw"]) for t in chain),
        "split_included": split_txid is not None,
        "split_txid": split_txid,
        "anchor": f"{file_id[:12]}:0",
    }

def handle_pcancel(params, rpc_config=None):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("BEGIN IMMEDIATE")

        c.execute("DELETE FROM priority_txs WHERE kind='pstore'")
        cancelled = c.rowcount

        new_txid = None
        new_vout = 0
        new_rs = None
        new_addr = None
        new_confirmed = 0

        anchor = _read_anchor(c)
        if anchor is not None:
            c.execute("SELECT 1 FROM priority_txs WHERE txid=?",
                      (anchor["txid"],))
            in_queue = c.fetchone()

            c.execute("SELECT spent FROM utxos WHERE txid=? AND vout=?",
                      (anchor["txid"], anchor["vout"]))
            u = c.fetchone()

            if in_queue:
                new_txid = anchor["txid"]
                new_vout = anchor["vout"]
                new_rs = anchor["redeem_script"]
                new_addr = anchor["address"]
                new_confirmed = 0
            elif u and u[0] == 0:
                new_txid = anchor["txid"]
                new_vout = anchor["vout"]
                new_rs = anchor["redeem_script"]
                new_addr = anchor["address"]
                new_confirmed = 1

        if new_txid is None:
            adopted = _try_adopt_existing_anchor(c)
            if adopted:
                new_txid = adopted["txid"]
                new_vout = adopted["vout"]
                new_rs = adopted["redeem_script"]
                new_addr = adopted["address"]
                new_confirmed = 1
                print(f"[PCANCEL] adopted anchor "
                      f"{new_txid[:12]}:{new_vout}")

        if new_txid is None:
            c.execute('''UPDATE pstore_anchor
                         SET txid=NULL, vout=NULL, redeem_script=NULL,
                             address=NULL, confirmed=0,
                             updated_at=strftime('%s','now')
                         WHERE id=1''')
            anchor_str = None
            print("[PCANCEL] anchor reset")
        else:
            _write_anchor(c, new_txid, new_vout, new_rs, new_addr, new_confirmed)
            anchor_str = f"{new_txid[:12]}:{new_vout}"
            print(f"[PCANCEL] anchor → {anchor_str} "
                  f"(confirmed={new_confirmed})")

        conn.commit()
    finally:
        conn.close()

    print(f"[PCANCEL] cancelled={cancelled} pstore txs")
    return {"cancelled": cancelled, "anchor": anchor_str}

def _is_op0_marker(vout):
    spk = vout.get("scriptPubKey") or {}
    return spk.get("asm", "").strip() == "0"


def _extract_opreturn_payload(vout):
    spk = vout.get("scriptPubKey") or {}
    asm = spk.get("asm", "")
    if asm.startswith("OP_RETURN"):
        rest = asm[len("OP_RETURN"):].strip()
        if rest:
            try:
                return bytes.fromhex(rest.replace(" ", ""))
            except ValueError:
                pass
    raw = spk.get("hex", "")
    if not raw.startswith("6a"):
        return None
    body = bytes.fromhex(raw[2:])
    if not body:
        return None
    push = body[0]
    if push <= 75:
        return body[1:1 + push]
    if push == 0x4c:
        return body[2:2 + body[1]]
    if push == 0x4d:
        n = int.from_bytes(body[1:3], "little")
        return body[3:3 + n]
    if push == 0x4e:
        n = int.from_bytes(body[1:5], "little")
        return body[5:5 + n]
    return None


def _has_trailing_op0(tx):
    vouts = tx.get("vout") or []
    if not vouts:
        return False
    return _is_op0_marker(vouts[-1])


def _fetch_chain(rpc_config, file_id, quiet=False):
    parts = []
    current = file_id
    depth = 0
    while True:
        tx = _rpc(rpc_config, "getrawtransaction", [current, 1])
        vouts = tx.get("vout") or []
        if not quiet:
            print(f"[PLOAD] tx[{depth}] {current[:12]}... ({len(vouts)} outs)")
        for vout in vouts:
            if _is_op0_marker(vout):
                continue
            payload = _extract_opreturn_payload(vout)
            if payload:
                parts.append(payload)

        if _has_trailing_op0(tx):
            break

        vins = tx.get("vin") or []
        if len(vins) != 1:
            raise RuntimeError(
                f"tx {current[:12]} has {len(vins)} inputs, expected 1"
            )
        prev_txid = vins[0].get("txid")
        if not prev_txid:
            raise RuntimeError(
                f"tx {current[:12]} input has no txid (coinbase?)"
            )
        current = prev_txid
        depth += 1

    if not parts:
        raise RuntimeError("no data found in chain")
    return b"".join(parts)


def _get_downloads_dir():
    import sys
    from pathlib import Path
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion"
                r"\Explorer\Shell Folders",
            )
            try:
                path, _ = winreg.QueryValueEx(
                    key, "{374DE290-123F-4565-9164-39C4925E467B}"
                )
            finally:
                winreg.CloseKey(key)
            return Path(path)
        except Exception:
            pass
    if sys.platform.startswith("linux"):
        xdg_config = Path(os.environ.get(
            "XDG_CONFIG_HOME", str(Path.home() / ".config")))
        user_dirs = xdg_config / "user-dirs.dirs"
        if user_dirs.is_file():
            try:
                for line in user_dirs.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("XDG_DOWNLOAD_DIR="):
                        val = line.split("=", 1)[1].strip().strip('"')
                        val = val.replace("$HOME", str(Path.home()))
                        return Path(val)
            except Exception:
                pass
    for name in ("Downloads", "Загрузки"):
        d = Path.home() / name
        if d.is_dir():
            return d
    return Path.home() / "Downloads"


def _unique_path(directory, filename):
    from pathlib import Path
    dest = directory / filename
    if not dest.exists():
        return dest
    stem, suffix = dest.stem, dest.suffix
    i = 1
    while True:
        cand = directory / f"{stem}_{i}{suffix}"
        if not cand.exists():
            return cand
        i += 1


def handle_pload(params, rpc_config, out_dir=None, overwrite=False):
    if not params:
        raise ValueError("pload: file_id required")

    file_id = str(params[0]).lower()
    ext = str(params[1]) if len(params) > 1 else "bin"
    ext = ext.lstrip(".") or "bin"

    if len(file_id) != 64 or not all(c in "0123456789abcdef" for c in file_id):
        raise ValueError(f"invalid file_id: {file_id!r}")
    if not ext.isalnum() or len(ext) > 16:
        raise ValueError(f"invalid extension: {ext!r}")

    print(f"[PLOAD] file_id={file_id} ext={ext} rpc={rpc_config['url']}")
    content = _fetch_chain(rpc_config, file_id, quiet=False)

    from pathlib import Path
    dest_dir = Path(out_dir) if out_dir else _get_downloads_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{file_id}.{ext}"
    dest = dest_dir / filename if overwrite else _unique_path(dest_dir, filename)

    tmp = dest.with_name(dest.name + ".part")
    try:
        with open(tmp, "wb") as f:
            f.write(content)
        os.replace(tmp, dest)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        raise

    print(f"[PLOAD] saved: {dest} ({len(content)} bytes)")
    return {
        "path": str(dest),
        "size": len(content),
        "file_id": file_id,
        "ext": ext,
    }
