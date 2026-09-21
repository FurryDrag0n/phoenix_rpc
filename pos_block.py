import hashlib
import struct
import time

from helpers import push_data, varint
from kernel_math import sha256d

BLOCK_VERSION = 6
COINBASE_FLAGS = bytes.fromhex("0372ea0000555a")  # default для testnet2

def encode_bip34_height(height: int) -> bytes:
    if height == 0:
        return b'\x00'
    result = bytearray()
    h = height
    while h > 0:
        result.append(h & 0xff)
        h >>= 8
    if result[-1] & 0x80:
        result.append(0x00)
    return bytes([len(result)]) + bytes(result)


def build_empty_coinbase(height: int, n_time: int,
                         extra_nonce: int = 1) -> bytes:
    script_sig = (
        encode_bip34_height(height)
        + push_data(bytes([extra_nonce & 0xff]))
        + COINBASE_FLAGS
    )

    tx = b""
    tx += struct.pack("<i", 1)                       # version
    tx += struct.pack("<I", n_time)                  # nTime
    tx += varint(1)                                  # vin count
    tx += b"\x00" * 32                               # prevout.hash
    tx += b"\xff\xff\xff\xff"                        # prevout.n
    tx += varint(len(script_sig)) + script_sig
    tx += b"\xff\xff\xff\xff"                        # sequence
    tx += varint(1)                                  # vout count
    tx += struct.pack("<q", 0)                       # amount = 0
    tx += varint(0)                                  # scriptPubKey = empty
    tx += struct.pack("<I", 0)                       # locktime
    return tx

def compute_merkle_root(tx_hashes: list) -> bytes:
    if not tx_hashes:
        return b'\x00' * 32
    layer = list(tx_hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def build_header(version: int, prevhash: bytes, merkleroot: bytes,
                 ntime: int, nbits: int, nnonce: int = 0) -> bytes:
    assert len(prevhash) == 32
    assert len(merkleroot) == 32
    return (
        struct.pack("<i", version)
        + prevhash
        + merkleroot
        + struct.pack("<I", ntime)
        + struct.pack("<I", nbits)
        + struct.pack("<I", nnonce)
    )

def build_pos_block(
        prev_hash: str,
        height: int,
        n_bits: int,
        n_time: int,
        coinbase_tx: bytes,
        coinstake_tx: bytes,
        scrypt_blockhash_func,
        sign_block_func,
) -> bytes:
    cb_hash = sha256d(coinbase_tx)
    cs_hash = sha256d(coinstake_tx)
    merkle_root = compute_merkle_root([cb_hash, cs_hash])

    prevhash_le = bytes.fromhex(prev_hash)[::-1]
    header = build_header(
        version=BLOCK_VERSION,
        prevhash=prevhash_le,
        merkleroot=merkle_root,
        ntime=n_time,
        nbits=n_bits,
        nnonce=0,
    )
    assert len(header) == 80

    block_hash_raw = scrypt_blockhash_func(header)
    vchBlockSig = sign_block_func(block_hash_raw)

    block = header
    block += varint(2)              # tx count
    block += coinbase_tx
    block += coinstake_tx
    block += varint(len(vchBlockSig))
    block += vchBlockSig

    return block

def assemble_pos_block(
        rpc,
        prev_hash: str,
        height: int,
        n_bits: int,
        n_time: int,
        coinbase_tx: bytes,
        coinstake_tx: bytes,
        scrypt_blockhash_func,
        sign_block_func,
        verbose: bool = False,
) -> dict:
    block = build_pos_block(
        prev_hash=prev_hash,
        height=height,
        n_bits=n_bits,
        n_time=n_time,
        coinbase_tx=coinbase_tx,
        coinstake_tx=coinstake_tx,
        scrypt_blockhash_func=scrypt_blockhash_func,
        sign_block_func=sign_block_func,
    )

    if verbose:
        header = block[:80]
        print(f"[pos_block] height    = {height}")
        print(f"[pos_block] prev      = {prev_hash[:16]}...")
        print(f"[pos_block] nTime     = {n_time}")
        print(f"[pos_block] nBits     = 0x{n_bits:08x}")
        print(f"[pos_block] total size= {len(block)} bytes")
        print(f"[pos_block] header    = {header.hex()}")

    return {
        "raw_block": block,
        "raw_hex": block.hex(),
    }
