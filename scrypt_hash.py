import hashlib

def scrypt_blockhash(header: bytes) -> bytes:
    return hashlib.scrypt(
        password=header,
        salt=header,
        n=1024,
        r=1,
        p=1,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )
