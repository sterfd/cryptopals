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

        if ml is None:
            ml = len(message) * 8

        length = pack("<Q", ml)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        message += b"\x80"
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        def left_rotate(bits, amount):
            return (bits << amount) | (bits >> (32 - amount))

        X = list(unpack("<" + "I" * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        print("round0", A, B, C, D)
        for i in range(16):
            k = i
            if i % 4 == 0:
                if i == 0:
                    print("0", A, self._F(B, C, D), X[0])
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xFFFFFFFF, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xFFFFFFFF, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xFFFFFFFF, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xFFFFFFFF, 19)
            if (i + 1) % 4 == 0:
                print("round1, group of 4", A, B, C, D)

        print("round1", A, B, C, D)
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

        print("round2", A, B, C, D)
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

        print("round3", A, B, C, D)

        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF

        print(self.A, self.B, self.C, self.D)

    def digest(self):
        return pack("<4I", self.A, self.B, self.C, self.D)

    def hex_digest(self):
        return hexlify(self.digest()).decode()


msg = b""
x = MD4(msg)
print(x)
