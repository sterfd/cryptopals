# Set 4 Challenge 28
# Implement a SHA-1 keyed MAC
"""
Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides 
(for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

SHA1(key || message)

Verify that you cannot tamper with the message without breaking the MAC you've produced, 
and that you can't produce a new MAC without knowing the secret key.

what is SHA - secure hashing algo
what is MAC - message authentication code - aka authentication tag

SHA-1 - 160 bit hash function resembling MD5
"""
import base64


def SHA1(message: bytes) -> int:
    def lrotate(bits, amount):
        return ((bits << amount) | (bits >> (32 - amount))) & 0xFFFFFFFF

    def fk(i, b, c, d):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40 or i >= 60:
            f = b ^ c ^ d
            k = 0x6ED9EBA1 if i < 40 else 0xCA62C1D6
        else:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        return f, k

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    mask = 0xFFFFFFFF

    # preprocess
    add_zeros = (119 - (len(message) % 64)) % 64
    message += (
        bytes([128])
        + bytes(add_zeros)
        + (len(message) * 8).to_bytes(8, byteorder="big")
    )

    # split into 64 byte chunks
    for chunk_idx in range(len(message) // 64):
        chunk = message[chunk_idx * 64 : (chunk_idx + 1) * 64]
        word_bytes = [chunk[i * 4 : (i + 1) * 4] for i in range(16)]
        words = [int.from_bytes(x, byteorder="big") for x in word_bytes]

        for i in range(16, 80):  # expand each block of 16 bytes to 80
            w_i = words[i - 3] ^ words[i - 8] ^ words[i - 16] ^ words[i - 14]
            words.append(lrotate(w_i, 1))

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            f, k = fk(i, b, c, d)
            temp = lrotate(a, 5) + f + e + k + words[i] & mask
            e, d = d, c
            c = lrotate(b, 30)
            b, a = a, temp

        h0 = (h0 + a) & mask
        h1 = (h1 + b) & mask
        h2 = (h2 + c) & mask
        h3 = (h3 + d) & mask
        h4 = (h4 + e) & mask

    return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4


# message = b"The lazy fox jumps over the lazy brown dog"
# x = SHA1(message)

# print(
#     base64.b64encode(bytes.fromhex(hex(x)[2:])),
#     hex(x),
# )
