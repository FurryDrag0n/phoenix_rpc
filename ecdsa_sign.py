import hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize, sigdecode_der

PRIVKEY = 1
# ВНИМАНИЕ: этот ключ используется как костыль для подписи заголовка PoS блока,
# он не подписывает какую-либо важную информацию или транзакции.
# хранение монет на адресе с этим ключом повлечёт их кражу

# compressed pubkey для privkey=1
HARDCODED_PUBKEY_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

def get_hardcoded_pubkey() -> bytes:
    return bytes.fromhex(HARDCODED_PUBKEY_HEX)

def sign_block_hash(block_hash: bytes) -> bytes:
    assert len(block_hash) == 32
    sk = SigningKey.from_secret_exponent(PRIVKEY, curve=SECP256k1)
    return sk.sign_digest_deterministic(
        block_hash,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_der_canonize,
    )

def verify_block_hash(block_hash: bytes, signature: bytes) -> bool:
    sk = SigningKey.from_secret_exponent(PRIVKEY, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return vk.verify_digest(signature, block_hash, sigdecode=sigdecode_der)
