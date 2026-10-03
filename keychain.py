import os
import struct
import hashlib
import getpass
import gostcrypto
import oqs

KEYPAIR_FILE = "keypair.bin"
MAGIC = b"S58"
MAGIC_LEN = len(MAGIC)
VERSION = 1

CIPHER = "kuznechik"
SALT_SIZE = 16
NONCE_SIZE = 8

KEY_LEN = 32
MAC_KEY_LEN = 32
MAC_LEN = 16

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

def derive_keys(password: bytes, salt: bytes):
    material = hashlib.scrypt(
        password,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN + MAC_KEY_LEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return bytearray(material[:KEY_LEN]), bytearray(material[KEY_LEN:])

def encrypt_keypair(pubkey: bytes, secret: bytes, password: bytes) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = derive_keys(password, salt)

    plaintext = (
        struct.pack("<I", len(pubkey)) + pubkey +
        struct.pack("<I", len(secret)) + secret
    )

    cipher = gostcrypto.gostcipher.new(
        CIPHER, enc_key, gostcrypto.gostcipher.MODE_CTR,
        init_vect=nonce
    )
    ciphertext = cipher.encrypt(plaintext)

    mac_obj = gostcrypto.gostcipher.new(
        CIPHER, mac_key, gostcrypto.gostcipher.MODE_MAC
    )
    mac_obj.update(ciphertext)
    mac = mac_obj.digest(MAC_LEN)

    return MAGIC + bytes([VERSION]) + salt + nonce + ciphertext + mac

def decrypt_keypair(blob: bytes, password: bytes):
    if len(blob) < MAGIC_LEN + 1 + SALT_SIZE + NONCE_SIZE + MAC_LEN:
        raise ValueError("File too short")

    if blob[:MAGIC_LEN] != MAGIC:
        raise ValueError("Unknown magic")

    version = blob[MAGIC_LEN]
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    off = MAGIC_LEN + 1
    salt = blob[off:off + SALT_SIZE]; off += SALT_SIZE
    nonce = blob[off:off + NONCE_SIZE]; off += NONCE_SIZE
    mac = blob[-MAC_LEN:]
    ciphertext = blob[off:-MAC_LEN]

    enc_key, mac_key = derive_keys(password, salt)

    mac_obj = gostcrypto.gostcipher.new(
        CIPHER, mac_key, gostcrypto.gostcipher.MODE_MAC
    )
    mac_obj.update(ciphertext)
    expected_mac = mac_obj.digest(MAC_LEN)

    if not hmac_compare(mac, expected_mac):
        raise ValueError("Wrong password or corrupted file")

    cipher = gostcrypto.gostcipher.new(
        CIPHER, enc_key, gostcrypto.gostcipher.MODE_CTR,
        init_vect=nonce
    )
    plaintext = cipher.decrypt(ciphertext)

    off = 0
    pub_len = struct.unpack("<I", plaintext[off:off + 4])[0]; off += 4
    pubkey = bytes(plaintext[off:off + pub_len]); off += pub_len
    sec_len = struct.unpack("<I", plaintext[off:off + 4])[0]; off += 4
    secret = bytes(plaintext[off:off + sec_len])

    return pubkey, secret

def hmac_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def get_or_create_keypair(password: str = None):
    if os.path.exists(KEYPAIR_FILE):
        if password is None:
            password = getpass.getpass("Wallet password: ")
        with open(KEYPAIR_FILE, "rb") as f:
            blob = f.read()
        return decrypt_keypair(blob, password.encode("utf-8"))

    if password is None:
        p1 = getpass.getpass("Please, set wallet password: ")
        p2 = getpass.getpass("Repeat wallet password: ")
        if p1 != p2:
            raise ValueError("Passwords do not match")
        password = p1

    with oqs.Signature("Falcon-512") as signer:
        pubkey = signer.generate_keypair()
        secret = signer.export_secret_key()

    blob = encrypt_keypair(pubkey, secret, password.encode("utf-8"))
    with open(KEYPAIR_FILE, "wb") as f:
        f.write(blob)
    os.chmod(KEYPAIR_FILE, 0o600)

    return pubkey, secret
