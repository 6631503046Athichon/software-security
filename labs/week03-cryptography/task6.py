import hashlib
from argon2 import PasswordHasher
import argon2.exceptions as ae

ph = PasswordHasher()  # argon2id + สุ่ม salt ต่อรหัสอัตโนมัติ

def store_password(pw: str) -> str:
    return ph.hash(pw)

def _is_argon2(s: str) -> bool:
    return s.startswith("$argon2")

def verify_password(record: dict, pw: str) -> bool:
    stored = record["pw"]
    if not _is_argon2(stored):                       # legacy MD5 32-hex
        if hashlib.md5(pw.encode()).hexdigest() == stored:
            record["pw"] = store_password(pw)        # rehash-on-login
            return True
        return False
    try:
        ph.verify(stored, pw)
    except (ae.VerifyMismatchError, ae.InvalidHash):
        return False
    if ph.check_needs_rehash(stored):
        record["pw"] = store_password(pw)
    return True

# ----- ส่วนทดสอบ (ให้เห็นการอัปเกรด MD5 -> argon2id) -----
if __name__ == "__main__":
    rec = {"pw": hashlib.md5(b"password123").hexdigest()}
    print("before (MD5):", rec["pw"])
    print("login correct:", verify_password(rec, "password123"))  # True + อัปเกรด
    print("after (argon2):", rec["pw"])                            # $argon2id$...
    print("wrong pw:", verify_password(rec, "nope"))               # False