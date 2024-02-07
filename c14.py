# Set 2 Challenge 14

# Byte-at-a-time ECB decryption (Harder)
# Take your oracle function from #12.
# Now generate a random count of random bytes and prepend this string to every plaintext.

# You are now doing:

# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# Same goal: decrypt the target-bytes.

# Stop and think for a second.
# What's harder than challenge #12 about doing this?
# How would you overcome that obstacle?
# The hint is: you're using all the tools you already have; no crazy math is required.

# Think "STIMULUS" and "RESPONSE".

import random
import base64
from cryptopals_functions import encrypt_AES_ECB


class Oracle:
    def __init__(self):
        self.key = random.randbytes(16)
        self.head = random.randbytes(random.randint(0, 16))
        self.tail = base64.b64decode(
            """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
        )
        self.num_calls = 0

    def encrypt_message(self, plaintext: bytes) -> bytes:
        self.num_calls += 1
        return encrypt_AES_ECB(self.head + plaintext + self.tail, self.key)


def separate_tail() -> (int, int, int):
    n = 31
    cipher_blocks = []
    while len(cipher_blocks) == len(set(cipher_blocks)):
        n += 1
        pad = bytes([0]) * n
        ciphertext = oracle.encrypt_message(pad)
        num_blocks = len(ciphertext) // 16
        cipher_blocks = [ciphertext[q * 16 : (q + 1) * 16] for q in range(num_blocks)]
    for i, block in enumerate(cipher_blocks):
        if cipher_blocks[i + 1] == block:
            pad_start = (i + 1) * 16
            tail_len = len(ciphertext) - (i + 2) * 16
            return n, pad_start, tail_len


def decrypt_tail_1x1(pad_len: int, start_idx: int, tail_len: int) -> bytes:
    plaintext = b""
    for tail_block in range(tail_len // 16 + 1):
        pad = bytes(pad_len - 1)
        target = start_idx + (tail_block + 1) * 16
        for _ in range(16):
            std_cipher = oracle.encrypt_message(pad)[start_idx:target]
            for b in range(256):
                test_cipher = oracle.encrypt_message(pad + plaintext + bytes([b]))
                if test_cipher[start_idx:target] == std_cipher:
                    plaintext += bytes([b])
                    pad = pad[1:]
                    break
    return plaintext


def check_blocks(ciphertext: bytes, std: bytes) -> bytes:
    block_len = len(std)
    for block_num in range(len(ciphertext) // block_len + 1):
        block = ciphertext[block_num * block_len : (block_num + 1) * block_len]
        if block == std:
            print(block_num, std, len(std))
            return bytes([block_num])


def decrypt_tail_scattershot(pad_len: int, start: int, tail_len: int) -> bytes:
    plaintext = b""
    for tail_block in range(tail_len // 16 + 1):
        target = start + (tail_block + 1) * 16
        for block_i in range(1, 17):
            std_cipher = oracle.encrypt_message(bytes(pad_len - block_i))[start:target]
            padding = [bytes(pad_len)]
            for b in range(1, 256):
                padding.append(bytes(16 - block_i) + plaintext + bytes([b]))
            test_cipher = oracle.encrypt_message(b"".join(padding))
            ch = check_blocks(test_cipher[start:], std_cipher)
            if not ch:
                print(
                    16 - block_i,
                    plaintext,
                    bytes([48]),
                    oracle.encrypt_message(
                        bytes(16 - block_i) + plaintext + bytes([48])
                    )[start:target],
                )
                print(pad_len, pad_len - block_i, std_cipher)
                return plaintext
            plaintext += ch
    print(plaintext, len(plaintext))


tail_blocks = {}
oracle = Oracle()
padding_len, padblock_idx, tail_len = separate_tail()
# plaintext = decrypt_tail_1x1(padding_len, padblock_idx, tail_len)
# print(len(oracle.head), padding_len, padblock_idx, tail_len)
# print(plaintext, oracle.num_calls)
pt = decrypt_tail_scattershot(padding_len, padblock_idx, tail_len)
print(pt, len(pt))
