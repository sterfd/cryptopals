# Set 1 Challenge 7

# AES in ECB mode
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters;
# I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

# Decrypt it. You know the key, after all.

# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

# Do this with code.
# You can obviously decrypt this using the OpenSSL command-line tool,
# but we're having you get ECB working in code for a reason.
# You'll need it a lot later on, and not just for attacking ECB.

import base64
from Crypto.Cipher import AES


def decrypt_AES_ECB(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(message)


key = "YELLOW SUBMARINE"
key_bytes = bytes(key, encoding="utf-8")

f = open("c7.txt", "r")
encrypted_bytes = base64.b64decode(f.read())

plain_text = decrypt_AES_ECB(encrypted_bytes, key_bytes)
print(plain_text)
