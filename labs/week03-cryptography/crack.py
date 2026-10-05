import hashlib

# อ่าน hash เป้าหมาย (ข้ามบรรทัด comment)
with open("hashes.txt", encoding="utf-8") as f:
    targets = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}

found = {}
with open("rockyou.txt", encoding="latin-1", errors="ignore") as f:
    for line in f:
        w = line.rstrip("\r\n")
        if hashlib.md5(w.encode("latin-1", "ignore")).hexdigest() in targets:
            found[hashlib.md5(w.encode("latin-1","ignore")).hexdigest()] = w
            print(hashlib.md5(w.encode("latin-1","ignore")).hexdigest() + ":" + w)
            if len(found) == len(targets):
                break
print("\ncracked %d/%d" % (len(found), len(targets)))