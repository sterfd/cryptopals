# Set 4 Challenge 25
# Break "random access read/write" AES CTR

# Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise)
#   under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

# Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext.
#   Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

# Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext;
#   the attacker has the ciphertext and controls the offset and "new text".

# Recover the original plaintext.

# **Food for thought.**
#   A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext;
#   to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream.
#   Imagine if you'd relied on that advice to, say, encrypt a disk.


import base64
import random
from cryptopals_functions import encrypt_CTR, decrypt_CBC
from Crypto.Cipher import AES


class CTREditOracle:
    def __init__(self):
        self.pt = self.get_pt()
        self.key = random.randbytes(16)
        self.keystream = self.generate_keystream()

    def get_pt(self):
        with open("c10.txt", "r") as f:
            ct = base64.b64decode(f.read())
            return decrypt_CBC(ct, bytes(16), b"YELLOW SUBMARINE")

    def generate_keystream(self):
        cipher = AES.new(self.key, AES.MODE_ECB)
        nonce = 0
        keystream = b""
        for block in range((len(self.pt) // 16) + 1):
            counter = nonce.to_bytes(
                length=16 // 2, byteorder="little"
            ) + block.to_bytes(length=16 // 2, byteorder="little")
            keystream += cipher.encrypt(counter)
        return keystream

    def get_ct(self):
        return encrypt_CTR(self.pt, 0, self.key)

    def edit(self, ct, offset, newtext):
        ct = bytearray(ct)
        for i, b in enumerate(newtext):
            ct[offset + i] = self.keystream[offset + i] ^ b
        return bytes(ct)


oracle = CTREditOracle()
ct = oracle.get_ct()
keystream = oracle.edit(ct, 0, bytes(len(ct)))
plaintext = bytes([c ^ k for c, k in zip(ct, keystream)])
print(plaintext)
