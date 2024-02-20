# Set 3 Challenge 20
# Break fixed-nonce CTR statistically


# In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

# Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

# Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

# To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

# Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.

import base64
import random
from c18 import encrypt_CTR
from cryptopals_functions import xor_key

key = random.randbytes(16)
f = open("c20.txt", "r")
decoded = [base64.b64decode(line) for line in f.readlines()]
ct = [bytearray(encrypt_CTR(dec, 0, key)) for dec in decoded]


def no_noncesense(ct):
    shortest_ct = min([len(text) for text in ct])
    ct = [text[:shortest_ct] for text in ct]
    pt = [b"" for _ in range(len(ct))]
    for idx in range(shortest_ct):
        ct_idx = [text[idx] for text in ct]
        best_score, best_bytes = 100, None
        for i in range(0, 255):
            score, decoded_bytes = xor_key(ct_idx, i)
            if score < best_score:
                best_score = score
                best_bytes = decoded_bytes
        for block, byte in enumerate(best_bytes):
            pt[block] += bytes([byte])
    return pt


plaintext = no_noncesense(ct)
for text in plaintext:
    print(text)
