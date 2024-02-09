# Set 2 Challenge 12

# Byte-at-a-time ECB decryption (Simple)

# Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key
#   (for instance, assign a single random key, once, to a global variable).

# Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

# Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
# aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
# dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
# YnkK

# Spoiler alert.
# Do not decode this string now. Don't do it.

# Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it.
#   The point is that you don't know its contents.

# What you have now is a function that produces:

# AES-128-ECB(your-string || unknown-string, random-key)
# It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

# Here's roughly how:

# Feed identical bytes of your-string to the function 1 at a time
#   --- start with 1 byte ("A"), then "AA", then "AAA" and so on.
#       Discover the block size of the cipher. You know it, but do this step anyway.

# Detect that the function is using ECB. You already know, but do this step anyways.

# Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA").
#   Think about what the oracle function is going to put in that last byte position.

# Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance,
#   "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

# Match the output of the one-byte-short input to one of the entries in your dictionary.
#   You've now discovered the first byte of unknown-string.

# Repeat for the next byte.


# Congratulations.
# This is the first challenge we've given you whose solution will break real crypto.
# Lots of people know that when you encrypt something in ECB mode, you can see penguins through it.
# Not so many of them can decrypt the contents of those ciphertexts, and now you can.
# If our experience is any guideline, this attack will get you code execution in security tests about once a year.

import random
import base64
from cryptopals_functions import encrypt_AES_ECB


class Oracle:
    def __init__(self):
        self.key = random.randbytes(16)
        self.tail = base64.b64decode(
            """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
        )
        self.num_calls = 0

    def encrypt_message(self, plaintext: bytes) -> bytes:
        self.num_calls += 1
        return encrypt_AES_ECB(plaintext + self.tail, self.key)


def ecb_byte_time() -> (bytes, int):
    cipher_blocks = {}

    def find_blocksize() -> (int, int):
        first_len = len(ecb_oracle.encrypt_message(bytes(0)))
        for i in range(100):
            ct = ecb_oracle.encrypt_message(bytes(i))
            if len(ct) > first_len:
                bs = len(ct) - first_len
                message_len = first_len - i
                return bs, message_len

    def confirm_ecb(bs: int) -> bool:
        ct = ecb_oracle.encrypt_message(bytes(bs * 3))
        if len(ct) == len(set(ct)):
            return False
        return True

    def decrypt_tail_1x1(bs: int, tail_len: int) -> bytes:
        decrypted = b""
        num_blocks = tail_len // bs + 1
        for block in range(num_blocks):
            start, end = block * 16, (block + 1) * 16
            for pad in range(15, -1, -1):
                std = ecb_oracle.encrypt_message(bytes(pad))
                for i in range(256):
                    ct = ecb_oracle.encrypt_message(bytes(pad) + decrypted + bytes([i]))
                    if ct[start:end] == std[start:end]:
                        decrypted += bytes([i])
                        break
        return decrypted

    def generate_blocks(bs):
        for pad in range(16):
            cipher = ecb_oracle.encrypt_message(bytes(pad))
            for block_num in range(len(cipher) // bs):
                block = cipher[block_num * bs : (block_num + 1) * bs]
                cipher_blocks[(pad, block_num)] = block

    def decrypt_tail_all(bs: int, tail_len: int) -> bytes:
        decrypted = b""
        for i in range(tail_len + 1):
            padding = []
            pad_block = bytes(15 - i) + decrypted if i < 16 else decrypted[-15:]
            for ch in range(256):
                padding.append(pad_block + bytes([ch]))
            ch_ciphertext = ecb_oracle.encrypt_message(b"".join(padding))
            offset = 15 - i % 16
            block = i // 16
            for ch in range(256):
                test_ch = ch_ciphertext[ch * bs : (ch + 1) * bs]
                if cipher_blocks[(offset, block)] == test_ch:
                    decrypted += bytes([ch])
                    break
        return decrypted

    ecb_oracle = Oracle()
    blocksize, tail_len = find_blocksize()
    if not confirm_ecb(blocksize):
        return "Oh no not ecb encryption"
    # plain_text = decrypt_tail_1x1(blocksize, tail_len)
    generate_blocks(blocksize)
    plain_text = decrypt_tail_all(blocksize, tail_len)

    return plain_text, ecb_oracle.num_calls


plaintext, oracle_calls = ecb_byte_time()
print(plaintext)
print(oracle_calls)
