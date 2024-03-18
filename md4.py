from random import randint
from binascii import unhexlify, hexlify
from struct import pack, unpack


class MD4:
    """Adapted from: https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py"""

    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(
        self, message, ml=None, A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476
    ):
        self.A, self.B, self.C, self.D = A, B, C, D
        self.chunk = None

        if ml is None:
            ml = len(message) * 8

        length = pack("<Q", ml)

        while len(message) > 64:
            return self._handle(message[:64])
            message = message[64:]

        message += b"\x80"
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        # print("preprocessed", message, int.from_bytes(message, byteorder="little"))

        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        self.chunk = chunk

        def left_rotate(bits, amount):
            return (bits << amount) | (bits >> (32 - amount))

        X = list(unpack("<" + "I" * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        # print("round0", A, B, C, D)
        for i in range(16):
            k = i
            if i % 4 == 0:
                # if i == 0:
                #     print("0", A, self._F(B, C, D), X[0])
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xFFFFFFFF, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xFFFFFFFF, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xFFFFFFFF, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xFFFFFFFF, 19)
            # if (i + 1) % 4 == 0:
            #     print("round1, group of 4", A, B, C, D)
            if i == 3:
                return A, B, C, D

        # print("round1", A, B, C, D)
        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate(
                    (A + self._G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, 3
                )
            elif i % 4 == 1:
                D = left_rotate(
                    (D + self._G(A, B, C) + X[k] + 0x5A827999) & 0xFFFFFFFF, 5
                )
            elif i % 4 == 2:
                C = left_rotate(
                    (C + self._G(D, A, B) + X[k] + 0x5A827999) & 0xFFFFFFFF, 9
                )
            elif i % 4 == 3:
                B = left_rotate(
                    (B + self._G(C, D, A) + X[k] + 0x5A827999) & 0xFFFFFFFF, 13
                )

        # print("round2", A, B, C, D)
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate(
                    (A + self._H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 3
                )
            elif i % 4 == 1:
                D = left_rotate(
                    (D + self._H(A, B, C) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 9
                )
            elif i % 4 == 2:
                C = left_rotate(
                    (C + self._H(D, A, B) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 11
                )
            elif i % 4 == 3:
                B = left_rotate(
                    (B + self._H(C, D, A) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 15
                )

        # print("round3", A, B, C, D)

        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF

        # print(self.A, self.B, self.C, self.D)

    def digest(self):
        return pack("<4I", self.A, self.B, self.C, self.D)

    def hex_digest(self):
        return hexlify(self.digest()).decode()


def MD3(msg):
    def lrotate(bits, amount):
        return ((bits << amount) | (bits >> (32 - amount))) & mask

    def round1(a, b, c, d):
        def f(x, y, z):
            return (x & y) | (~x & z)  # xy v (-x)z - if x then y else z

        def r1_op(A, B, C, D, I, S):
            if I == 0:
                print(I, A, f(B, C, D), X[I])
            return lrotate((A + f(B, C, D) + X[I]) & mask, S)

        for x in range(4):
            a = r1_op(a, b, c, d, x * 4, 3)
            d = r1_op(d, a, b, c, x * 4 + 1, 7)
            c = r1_op(c, d, a, b, x * 4 + 2, 11)
            b = r1_op(b, c, d, a, x * 4 + 3, 19)
            print("round1 group4", a, b, c, d)
            return a, b, c, d

    def round2(a, b, c, d):
        r2 = 0x5A827999

        def g(x, y, z):
            return (
                (x & y) | (x & z) | (y & z)
            )  # xy v xz v yz - if two of xyz is 1, g is 1

        def r2_op(A, B, C, D, I, S):
            return lrotate((A + g(B, C, D) + X[I] + r2) & mask, S)

        for x in range(4):
            a = r2_op(a, b, c, d, x, 3)
            d = r2_op(d, a, b, c, x + 4, 5)
            c = r2_op(c, d, a, b, x + 8, 9)
            b = r2_op(b, c, d, a, x + 12, 13)
        return a, b, c, d

    def round3(a, b, c, d):
        r3 = 0x6ED9EBA1

        def h(x, y, z):
            return x ^ y ^ z

        def r3_op(A, B, C, D, I, S):
            return lrotate((A + h(B, C, D) + X[I] + r3) & mask, S)

        for x in [0, 2, 1, 3]:
            a = r3_op(a, b, c, d, x, 3)
            d = r3_op(d, a, b, c, x + 8, 9)
            c = r3_op(c, d, a, b, x + 4, 11)
            b = r3_op(b, c, d, a, x + 12, 15)
        return a, b, c, d

    A = 0x01234567  # little byteorder
    B = 0x89ABCDEF
    C = 0xFEDCBA98
    D = 0x766543210

    rA = 0x67452301
    rB = 0xEFCDAB89
    rC = 0x98BADCFE
    rD = 0x10325476
    mask = 0xFFFFFFFF

    # preprocess and padding
    add_zeros = (119 - (len(msg) % 64)) % 64
    msg += (
        bytes([128]) + bytes(add_zeros) + (len(msg) * 8).to_bytes(8, byteorder="little")
    )
    # print(msg, int.from_bytes(msg, byteorder="little"))

    for chunk_idx in range(len(msg) // 64):
        chunk = msg[chunk_idx * 64 : (chunk_idx + 1) * 64]

        word_bytes = [chunk[i * 4 : (i + 1) * 4] for i in range(16)]
        M = [int.from_bytes(x, byteorder="little") for x in word_bytes]

        # for i in range(len(M)):
        X = M  # [M[i * 16 + j] for j in range(16)]
        AA, BB, CC, DD = rA, rB, rC, rD
        print("round0", rA, rB, rC, rD)
        rA, rB, rC, rD = round1(rA, rB, rC, rD)
        return rA, rB, rC, rD, chunk
        print("round1", rA, rB, rC, rD)
        rA, rB, rC, rD = round2(rA, rB, rC, rD)
        # print("round2", rA, rB, rC, rD)
        rA, rB, rC, rD = round3(rA, rB, rC, rD)
        # print("round3", rA, rB, rC, rD)
        rA = (rA + AA) & mask
        rB = (rB + BB) & mask
        rC = (rC + CC) & mask
        rD = (rD + DD) & mask

        print(rA, rB, rC, rD)

    return (rA << 96) | (rB << 64) | (rC << 32) | rD


# msgs = [
#     b"The quick brown fox jumps over the lazy dog",
#     b"The quick brown fox jumps over the lazy cog",
#     b"",
# ]
# hashes = [
#     0x1BEE69A46BA811185C194762ABAEAE90,
#     0xB86E130CE7028DA59E672D56AD0113DF,
#     0x31D6CFE0D16AE931B73C59D7E0C089C0,
# ]

# for m, h in zip(msgs, hashes):
#     hash = MD4(m)
#     print(hex(hash))

ra, rb, rc, rd, r_chunk = MD3(b"a")
print("md3", ra, rb, rc, rd)

msg = b"a"
x = MD4(msg)
print("md4", x.A, x.B, x.C, x.D)


print((ra == x.A) & (rb == x.B) & (rc == x.C) & (rd == x.D))
print(r_chunk)
print(x.chunk)
