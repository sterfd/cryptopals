# Set 4 Challenge 30
# Break an MD4 keyed MAC using length extension

"""
Second verse, same as the first, but use MD4 instead of SHA-1. 
    Having done this attack once against SHA-1, 
    the MD4 variant should take much less time; 
    mostly just the time you'll spend Googling for an implementation of MD4.


**You're thinking, why did we bother with this?
    Blame Stripe. In their second CTF game, 
    the second-to-last challenge involved breaking an H(k, m) MAC with SHA1. 
    Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
"""


# def failed_MD4(msg):
#     def lrotate(bits, amount):
#         return (bits << amount) | (bits >> (32 - amount))

#     def round1(a, b, c, d, X):
#         def f(x, y, z):
#             return (x & y) | (~x & z)  # xy v (-x)z - if x then y else z

#         def r1_op(A, B, C, D, I, S):
#             return lrotate((A + f(B, C, D) + X[I]) & mask, S)

#         for x in range(4):
#             a = r1_op(a, b, c, d, x * 4, 3)
#             d = r1_op(d, a, b, c, x * 4 + 1, 7)
#             c = r1_op(c, d, a, b, x * 4 + 2, 11)
#             b = r1_op(b, c, d, a, x * 4 + 3, 19)
#         return a, b, c, d

#     def round2(a, b, c, d, X):
#         r2 = 0x5A827999

#         def g(x, y, z):
#             return (x & y) | (x & z) | (y & z)

#         # xy v xz v yz - if two of xyz is 1, g is 1

#         def r2_op(A, B, C, D, I, S):
#             return lrotate((A + g(B, C, D) + X[I] + r2) & mask, S)

#         for x in range(4):
#             a = r2_op(a, b, c, d, x, 3)
#             d = r2_op(d, a, b, c, x + 4, 5)
#             c = r2_op(c, d, a, b, x + 8, 9)
#             b = r2_op(b, c, d, a, x + 12, 13)
#         return a, b, c, d

#     def round3(a, b, c, d, X):
#         r3 = 0x6ED9EBA1

#         def h(x, y, z):
#             return x ^ y ^ z

#         def r3_op(A, B, C, D, I, S):
#             return lrotate((A + h(B, C, D) + X[I] + r3) & mask, S)

#         for x in [0, 2, 1, 3]:
#             a = r3_op(a, b, c, d, x, 3)
#             d = r3_op(d, a, b, c, x + 8, 9)
#             c = r3_op(c, d, a, b, x + 4, 11)
#             b = r3_op(b, c, d, a, x + 12, 15)
#         return a, b, c, d

#     A = 0x67452301
#     B = 0xEFCDAB89
#     C = 0x98BADCFE
#     D = 0x10325476
#     mask = 0xFFFFFFFF

#     # preprocess and padding
#     add_zeros = (119 - (len(msg) % 64)) % 64
#     msg_bitlen = len(msg) * 8
#     msg += bytes([128]) + bytes(add_zeros)
#     msg += msg_bitlen.to_bytes(8, byteorder="little")

#     # update internal states ABCD for each block of 512 bits
#     for chunk_idx in range(len(msg) // 64):
#         chunk = msg[chunk_idx * 64 : (chunk_idx + 1) * 64]
#         X = [
#             int.from_bytes(chunk[i : i + 4], byteorder="little")
#             for i in range(0, 64, 4)
#         ]
#         print(len(X), X)
#         AA, BB, CC, DD = A, B, C, D
#         A, B, C, D = round1(A, B, C, D, X)
#         A, B, C, D = round2(A, B, C, D, X)
#         A, B, C, D = round3(A, B, C, D, X)
#         A = (A + AA) & mask
#         B = (B + BB) & mask
#         C = (C + CC) & mask
#         D = (D + DD) & mask

#         print(A, B, C, D)

#     return (A << 96) | (B << 64) | (C << 32) | D


# msgs = [
#     b"The quick brown fox jumps over the lazy dog",
#     b"The quick brown fox jumps over the lazy cog",
#     b"",
#     b"a",
#     b"abc",
# ]
# hashes = [
#     0x1BEE69A46BA811185C194762ABAEAE90,
#     0xB86E130CE7028DA59E672D56AD0113DF,
#     0x31D6CFE0D16AE931B73C59D7E0C089C0,
# ]

# for m, h in zip(msgs, hashes):
#     hash = MD4(m)
#     print(hex(hash))

# hash = MD4(msgs[3])
# print(hex(hash))


# copied implemntation.....

import struct


class MD4:
    """An implementation of the MD4 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    # Unlike, say, SHA-1, MD4 uses little-endian. Fascinating!
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, msg=None):
        """:param ByteString msg: The message to be hashed."""
        if msg is None:
            msg = b""

        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        # Process the message in successive 512-bit chunks.
        self._process([msg[i : i + 64] for i in range(0, len(msg), 64)])

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack("<4L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode()

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


messages = [b"", b"The quick brown fox jumps over the lazy dog", b"BEES"]
print("Actual:  ", MD4(message).hexdigest())
"""
import random


def MD_padding(msg):
    add_zeros = (119 - (len(msg) % 64)) % 64
    return (
        bytes([128]) + bytes(add_zeros) + (len(msg) * 8).to_bytes(8, byteorder="little")
    )


msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
secret_prefix = random.randbytes(random.randint(16, 60))
hashed_msg = SHA1(secret_prefix + msg)
hex_hash = hex(hashed_msg)[2:]
if len(hex_hash) % 2 == 1:
    hex_hash = "0" + hex_hash
MAC = bytes.fromhex(hex_hash)


def forge_mac(new_msg):
    h = [MAC[i * 4 : (i + 1) * 4] for i in range(len(MAC) // 4)]
    h = [int.from_bytes(i, byteorder="little") for i in h]

    for guess in range(16, 61):
        glue_padding = MD_padding(bytes(guess) + msg)
        len_added = guess + len(msg) + len(glue_padding) + len(new_msg)

        forged_msg = SHA1_states(new_msg, h, len_added)
        final_msg = SHA1(secret_prefix + msg + glue_padding + new_msg)

        if forged_msg == final_msg:
            print("len of secret prefix", guess)
            print(hex(forged_msg))
            return True


new_msg = b";admin=true"
print(forge_mac(new_msg))

"""
