import hashlib
import struct
import toml

with open("config.toml") as f:
    config = toml.load(f)

F_TESTNET = bool(config["network"]["testnet"])

COIN     = 1_000_000
CENT     = 10_000
nOneDay  = 86_400
nOneHour = 3_600

nTargetTimespan = 7 * nOneDay

if F_TESTNET:
    nStakeMinAge        = 2 * nOneHour
    nStakeMaxAge        = 90 * nOneDay
    nStakeTargetSpacing = 5 * 60
    nModifierInterval   = 20 * 60
    nCoinbaseMaturity   = 10

    BN_POW_LIMIT        = ((1 << 256) - 1) >> 16
    BN_POS_LIMIT        = ((1 << 256) - 1) >> 27
else:
    nStakeMinAge        = 30 * nOneDay
    nStakeMaxAge        = 90 * nOneDay
    nStakeTargetSpacing = 10 * 60
    nModifierInterval   = 6 * nOneHour
    nCoinbaseMaturity   = 500

    BN_POW_LIMIT        = ((1 << 256) - 1) >> 20
    BN_POS_LIMIT        = ((1 << 256) - 1) >> 27

BN_POS_LEGACY       = ((1 << 256) - 1) >> 24
BN_POS_HARD         = ((1 << 256) - 1) >> 30

MAX_MINT_PROOF_OF_WORK  = 100 * COIN
MAX_MINT_PROOF_OF_STAKE = 1 * COIN

def set_compact(n_compact: int) -> int:
    n_size = (n_compact >> 24) & 0xFF
    f_negative = (n_compact & 0x00800000) != 0
    n_word = n_compact & 0x007FFFFF
    if n_size <= 3:
        value = n_word >> (8 * (3 - n_size))
    else:
        value = n_word << (8 * (n_size - 3))
    return -value if f_negative else value

def get_compact(value: int) -> int:
    f_negative = value < 0
    n = abs(value)
    n_size = (n.bit_length() + 7) // 8
    if n_size <= 3:
        n_compact = n << (8 * (3 - n_size))
    else:
        n_compact = n >> (8 * (n_size - 3))
    if n_compact & 0x00800000:
        n_compact >>= 8
        n_size += 1
    if f_negative and (n_compact & 0x007FFFFF):
        n_compact |= 0x00800000
    n_compact |= n_size << 24
    return n_compact

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def get_weight(t1: int, t2: int) -> int:
    return min(t2 - t1 - nStakeMinAge, nStakeMaxAge)

def compute_tx_offset(vtx_hex, tx_index: int) -> int:
    offset = 80 + len(varint(len(vtx_hex)))
    for i in range(tx_index):
        offset += len(vtx_hex[i]) // 2
    return offset

def check_stake_kernel_hash(n_bits, n_time_block_from, n_tx_prev_offset,
                            n_time_tx_prev, prevout_n, n_time_tx,
                            n_value_in, n_stake_modifier):
    if n_time_tx < n_time_tx_prev:
        return None
    if n_time_block_from + nStakeMinAge > n_time_tx:
        return None

    weight = get_weight(n_time_tx_prev, n_time_tx)
    if weight <= 0:
        return None

    coin_day_weight = (n_value_in * weight) // COIN // nOneDay
    target_per_coin_day = set_compact(n_bits)
    target = coin_day_weight * target_per_coin_day

    ss = struct.pack(
        '<QIIIII',
        n_stake_modifier & 0xFFFFFFFFFFFFFFFF,
        n_time_block_from & 0xFFFFFFFF,
        n_tx_prev_offset & 0xFFFFFFFF,
        n_time_tx_prev & 0xFFFFFFFF,
        prevout_n & 0xFFFFFFFF,
        n_time_tx & 0xFFFFFFFF,
    )
    hash_proof = sha256d(ss)

    hash_int = int.from_bytes(hash_proof, 'little')
    if hash_int > target:
        return None

    return {
        "hash_proof": hash_proof,
        "hash_proof_be": hash_proof[::-1],
        "hash_int": hash_int,
        "target": target,
        "weight": weight,
        "coin_day_weight": coin_day_weight,
        "ss": ss,
    }

def get_proof_of_stake_limit(n_height: int, n_time: int) -> int:
    if F_TESTNET:
        return BN_POS_LIMIT
    if n_time > 1450569600:
        return BN_POS_LIMIT
    if n_height + 1 > 15000:
        return BN_POS_LEGACY
    if n_height + 1 > 14060:
        return BN_POS_HARD
    return BN_POW_LIMIT

def get_coin_age(rpc, kernel_inputs, n_time: int):
    bn_cent_second = 0

    for txid, vout_n in kernel_inputs:
        try:
            tx = rpc("getrawtransaction", [txid, 1])
        except Exception:
            continue
        if n_time < tx["time"]:
            return None
        block_hash = tx.get("blockhash")
        if not block_hash:
            continue
        blk = rpc("getblock", [block_hash])
        if blk["time"] + nStakeMinAge > n_time:
            continue
        value_in = int(round(float(tx["vout"][vout_n]["value"]) * COIN))
        bn_cent_second += value_in * (n_time - tx["time"]) // CENT

    bn_coin_day = bn_cent_second * CENT // COIN // nOneDay
    return bn_coin_day


def get_proof_of_stake_reward(n_coin_age: int, n_bits: int, n_time: int,
                              b_coin_year_only: bool = False) -> int:
    n_reward_coin_year_limit = MAX_MINT_PROOF_OF_STAKE
    bn_target = set_compact(n_bits)

    bn_limit = get_proof_of_stake_limit(0, n_time)
    bn_limit = set_compact(get_compact(bn_limit))

    bn_lower = 1 * CENT
    bn_upper = n_reward_coin_year_limit

    while bn_lower + CENT <= bn_upper:
        bn_mid = (bn_lower + bn_upper) // 2
        bn_mid_part = bn_mid * bn_mid * bn_mid
        bn_reward_part = n_reward_coin_year_limit ** 3
        if bn_mid_part * bn_limit > bn_reward_part * bn_target:
            bn_upper = bn_mid
        else:
            bn_lower = bn_mid

    n_reward_coin_year = bn_upper
    n_reward_coin_year = min(
        (n_reward_coin_year // CENT) * CENT,
        MAX_MINT_PROOF_OF_STAKE,
    )

    if b_coin_year_only:
        return n_reward_coin_year

    n_subsidy = n_coin_age * n_reward_coin_year * 33 // (365 * 33 + 8)
    n_subsidy = min(n_subsidy, 10 * COIN)
    return n_subsidy

def _get_last_block_index(rpc, block_hash: str, want_pos: bool):
    cur_hash = block_hash
    while cur_hash:
        blk = rpc("getblock", [cur_hash])
        is_pos = "proof-of-stake" in blk.get("flags", "")
        if is_pos == want_pos:
            return blk
        prev = blk.get("previousblockhash")
        if not prev:
            return None
        cur_hash = prev
    return None

def get_next_target_required_pos(rpc, pindex_last_hash: str) -> int:
    pindex_prev = _get_last_block_index(rpc, pindex_last_hash, want_pos=True)
    if pindex_prev is None:
        return get_compact(get_proof_of_stake_limit(0, 0))

    bn_limit = get_proof_of_stake_limit(pindex_prev["height"], pindex_prev["time"])

    prev_prev_hash = pindex_prev.get("previousblockhash")
    if not prev_prev_hash:
        return get_compact(bn_limit)

    pindex_prev_prev = _get_last_block_index(rpc, prev_prev_hash, want_pos=True)
    if pindex_prev_prev is None or not pindex_prev_prev.get("previousblockhash"):
        return get_compact(bn_limit)

    n_actual_spacing = pindex_prev["time"] - pindex_prev_prev["time"]
    n_interval = nTargetTimespan // nStakeTargetSpacing

    bn_new = set_compact(int(pindex_prev["bits"], 16))
    bn_new *= (n_interval - 1) * nStakeTargetSpacing + 2 * n_actual_spacing
    bn_new //= (n_interval + 1) * nStakeTargetSpacing

    if bn_new > bn_limit:
        bn_new = bn_limit

    return get_compact(bn_new)
