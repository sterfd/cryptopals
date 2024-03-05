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
from cryptopals_functions import MT19937
import random


class CTREditOracle:
    def __init__(self, seed: int):
        self.seed = seed
        self.pt = self.get_pt()
        self.keystream = self.keystream_generator()

    def get_pt(self):
        with open("c25.txt", "r") as f:
            return base64.b64decode(f.read())

    def keystream_generator(self):
        pt_len = len(self.pt)
        gen = MT19937(self.seed)
        return [
            byte
            for _ in range(pt_len // 4 + 1)
            for byte in bytearray(gen.extract_numbers().to_bytes(4, byteorder="little"))
        ]

    def encrypt_CTR(self):
        return bytes([k ^ p for k, p in zip(self.keystream, self.pt)])

    def edit(self, ct, offset, newtext):
        # seek into ct, decrypt, reencrypt with different plaintext
        # exposed to attackers by API call that doesnt reveal key or original pt
        # attacker as ct and controls offset adn new text
        # recover original pt
        pass


seed = random.randint(0, 2**16)
oracle = CTREditOracle(seed)
ct = oracle.encrypt_CTR()

"""
ct[0] = pt[0] ^ ks[0]
edit: offset = 0
   new_ct[0] = new_pt[0] ^ks[0]

"""
