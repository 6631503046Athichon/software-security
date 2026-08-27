import os
from Crypto.Cipher import AES

def _key() -> bytes:
    key = bytes.fromhex(os.environ["ENC_KEY_HEX"])   # key จาก env ไม่ hardcode
    if len(key) not in (16, 24, 32):
        raise ValueError("ENC_KEY_HEX must decode to 16/24/32 bytes")
    return key

def encrypt_gcm(pt: bytes):
    nonce = os.urandom(12)                            # nonce สุ่ม 12 byte ต่อ 1 ข้อความ
    c = AES.new(_key(), AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return nonce, ct, tag

def decrypt_gcm(nonce, ct, tag) -> bytes:
    c = AES.new(_key(), AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)             # ValueError ถ้าถูกแก้

if __name__ == "__main__":
    os.environ.setdefault("ENC_KEY_HEX", os.urandom(32).hex())
    nonce, ct, tag = encrypt_gcm(b"transfer 100USD to alice")
    print("decrypted:", decrypt_gcm(nonce, ct, tag))   # ถอดปกติได้
    bad = bytearray(ct); bad[0] ^= 1                    # พลิก 1 bit
    try:
        decrypt_gcm(nonce, bytes(bad), tag); print("BUG: not detected")
    except ValueError as e:
        print("tampered -> FAILED:", e)                # << MAC check failed