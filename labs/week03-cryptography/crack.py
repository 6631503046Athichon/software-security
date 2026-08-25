import hashlib

hashes = ["482c811da5d5b4bc6d497ffa98491e38",
          "e10adc3949ba59abbe56e057f20f883e",
          "25f9e794323b453885f5181f1b624d0b",
          "5f4dcc3b5aa765d61d8327deb882cf99"]

wordlist = ["password123", "123456", "password", "123456789"]

for word in wordlist:
    h = hashlib.md5(word.encode()).hexdigest()
    if h in hashes:
        print(h, "=", word)