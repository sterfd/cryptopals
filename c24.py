# Set 3 Challenge 24
# Create the MT19937 stream cipher and break it
# You can create a trivial stream cipher out of any PRNG;
#   use it to generate a sequence of 8 bit outputs and call those outputs a keystream.
#   XOR each byte of plaintext with each successive byte of keystream.

# Write the function that does this for MT19937 using a 16-bit seed.
#   Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

# Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

# From the ciphertext, recover the "key" (the 16 bit seed).

# Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

# Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.

from c21 import MT19937
import random
from time import time


def keystream_gen(seed, pt_len):
    gen = MT19937(seed)
    return [
        byte
        for _ in range(pt_len // 4 + 1)
        for byte in bytearray(gen.extract_numbers().to_bytes(4, byteorder="little"))
    ]


def encrypt_pt(seed, pt):
    prefix = random.randbytes(random.randint(6, 30))
    pt = prefix + pt
    keystream = keystream_gen(seed, len(pt))
    return bytes(k ^ p for k, p in zip(keystream, pt))


def decrypt_pt(seed, ct):
    keystream = keystream_gen(seed, len(ct))
    return bytes(k ^ c for k, c in zip(keystream, ct))


def message_fun():
    plaintext = b"A" * 14
    seed = random.randint(0, 2**16)
    ct = encrypt_pt(seed, plaintext)
    print(ct)

    for i in range(256**2):
        if decrypt_pt(i, ct)[-5:] == b"AAAAA":
            print("found seed", i)
            print("... actual seed", seed)


def password_token():
    pass
