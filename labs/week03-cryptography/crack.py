import hashlib
hashes = ["15da1f78ad7d474862865bab1aab4d51", "0192023a7bbd73250516f069df18b500"]
wordlist = ["alicepw", "admin123", "password", "123456"]
for w in wordlist:
    h = hashlib.md5(w.encode()).hexdigest()
    if h in hashes: print(h, "=", w)