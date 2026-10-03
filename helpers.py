import hashlib
import struct
import toml
from io import BytesIO

import base58

with open("config.toml") as f:
    config = toml.load(f)

F_TESTNET = bool(config["network"]["testnet"])

OP_DUP          = 0x76
OP_HASH160      = 0xa9
OP_EQUAL        = 0x87
OP_EQUALVERIFY  = 0x88
OP_CHECKSIG     = 0xac
OP_SHA1         = 0xa7
OP_SHA256       = 0xa8
OP_RETURN       = 0x6a
OP_DROP         = 0x75
OP_TRUE         = 0x51
OP_FALCONVERIFY = 0xb9

SIGHASH_ALL = 1
ONE_COIN    = 1_000_000

PUBKEY_SIZE  = 897
SIG_MAX_SIZE = 666
CHUNK_SIZE   = 520

MAX_OPRETURN_BYTES = 80

if F_TESTNET:
    PREFIX_P2PKH = 0x6F
    PREFIX_P2SH  = 0xC4
else:
    PREFIX_P2PKH = 0x08
    PREFIX_P2SH  = 0x14

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check_encode(payload: bytes, version_byte: int) -> str:
    versioned = bytes([version_byte]) + payload
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()

def base58_decode_check(addr: str):
    data = base58.b58decode(addr)
    if len(data) < 5:
        raise ValueError("Invalid address: too short")
    version = data[0]
    payload = data[1:-4]
    checksum = data[-4:]
    computed = hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4]
    if checksum != computed:
        raise ValueError("Invalid checksum")
    return version, payload

def push_data(data: bytes) -> bytes:
    n = len(data)
    if n <= 75:
        return bytes([n]) + data
    elif n <= 0xFF:
        return b'\x4c' + bytes([n]) + data
    elif n <= 0xFFFF:
        return b'\x4d' + struct.pack('<H', n) + data
    else:
        return b'\x4e' + struct.pack('<I', n) + data


def address_to_output_script(addr: str) -> bytes:
    version, h160 = base58_decode_check(addr)
    if version == PREFIX_P2PKH:
        return bytes([OP_DUP, OP_HASH160, 0x14]) + h160 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    elif version == PREFIX_P2SH:
        return bytes([OP_HASH160, 0x14]) + h160 + bytes([OP_EQUAL])
    else:
        raise ValueError(f"Unsupported address version: 0x{version:02x} "
                         f"(expected P2PKH=0x{PREFIX_P2PKH:02x} or P2SH=0x{PREFIX_P2SH:02x})")


def script_hash_to_script_pubkey(script_hash: bytes) -> bytes:
    return bytes([OP_HASH160, 0x14]) + script_hash + bytes([OP_EQUAL])


def build_opreturn(data: bytes) -> bytes:
    return bytes([OP_RETURN]) + push_data(data)


def build_script_sig(signature: bytes, pubkey: bytes, redeem_script: bytes) -> bytes:
    sig_chunks = chunks(signature, CHUNK_SIZE)
    key_chunks = chunks(pubkey, CHUNK_SIZE)
    while len(sig_chunks) < 2:
        sig_chunks.append(b'')
    while len(key_chunks) < 2:
        key_chunks.append(b'')
    parts = sig_chunks[::-1] + key_chunks[::-1] + [redeem_script]
    return b''.join(push_data(p) for p in parts)


def build_redeem_script(salt: bytes, pubkey_hash: bytes) -> bytes:
    return (
        push_data(salt) +
        bytes([OP_DROP]) +
        push_data(pubkey_hash) +
        bytes([OP_FALCONVERIFY]) +
        bytes([OP_DROP]) * 5 +
        bytes([OP_TRUE])
    )


def chunks(data: bytes, size: int):
    return [data[i:i+size] for i in range(0, len(data), size)]

def varint(n: int) -> bytes:
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def serialize_tx(version: int, ntime: int, inputs: list, outputs: list, locktime: int = 0) -> bytes:
    out = BytesIO()
    out.write(struct.pack('<I', version))
    out.write(struct.pack('<I', ntime))
    out.write(varint(len(inputs)))
    for txin in inputs:
        out.write(txin['txid'][::-1])
        out.write(struct.pack('<I', txin['vout']))
        script_sig = txin.get('scriptSig', b'')
        out.write(varint(len(script_sig)))
        out.write(script_sig)
        out.write(struct.pack('<I', txin.get('sequence', 0xffffffff)))
    out.write(varint(len(outputs)))
    for txout in outputs:
        out.write(struct.pack('<Q', txout['amount']))
        script = txout['script']
        out.write(varint(len(script)))
        out.write(script)
    out.write(struct.pack('<I', locktime))
    return out.getvalue()

def parse_tx(raw: bytes) -> dict:
    off = [0]

    def read(n):
        data = raw[off[0]:off[0] + n]
        if len(data) != n:
            raise ValueError(f"Unexpected end of tx at offset {off[0]}")
        off[0] += n
        return data

    def read_varint():
        b = raw[off[0]]
        if b < 0xfd:
            off[0] += 1
            return b
        elif b == 0xfd:
            v = struct.unpack_from('<H', raw, off[0] + 1)[0]
            off[0] += 3
            return v
        elif b == 0xfe:
            v = struct.unpack_from('<I', raw, off[0] + 1)[0]
            off[0] += 5
            return v
        else:
            v = struct.unpack_from('<Q', raw, off[0] + 1)[0]
            off[0] += 9
            return v

    version = struct.unpack('<I', read(4))[0]
    ntime   = struct.unpack('<I', read(4))[0]

    vin_count = read_varint()
    vin = []
    for _ in range(vin_count):
        prev_hash_internal = read(32)
        prev_n = struct.unpack('<I', read(4))[0]
        script_len = read_varint()
        script_sig = read(script_len)
        sequence = struct.unpack('<I', read(4))[0]
        vin.append({
            'txid': prev_hash_internal[::-1],
            'vout': prev_n,
            'scriptSig': script_sig,
            'sequence': sequence,
        })

    vout_count = read_varint()
    vout = []
    for _ in range(vout_count):
        amount = struct.unpack('<q', read(8))[0]
        script_len = read_varint()
        script = read(script_len)
        vout.append({'amount': amount, 'script': script})

    locktime = struct.unpack('<I', read(4))[0]

    if off[0] != len(raw):
        raise ValueError(f"Trailing {len(raw) - off[0]} bytes after tx")

    return {
        'version': version,
        'ntime': ntime,
        'vin': vin,
        'vout': vout,
        'locktime': locktime,
    }

def compute_txid(raw_tx: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()[::-1].hex()


def signature_hash(tx_version, ntime, inputs, outputs, n_in, script_code, n_hash_type, locktime=0):
    modified_inputs = []
    for i, txin in enumerate(inputs):
        new_txin = txin.copy()
        new_txin['scriptSig'] = script_code if i == n_in else b''
        modified_inputs.append(new_txin)
    tx_bytes = serialize_tx(tx_version, ntime, modified_inputs, outputs, locktime)
    tx_bytes += struct.pack('<I', n_hash_type)
    return hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
