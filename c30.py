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


def MD4(msg):
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


msgs = [
    b"The quick brown fox jumps over the lazy dog",
    b"The quick brown fox jumps over the lazy cog",
    b"",
]
hashes = [
    0x1BEE69A46BA811185C194762ABAEAE90,
    0xB86E130CE7028DA59E672D56AD0113DF,
    0x31D6CFE0D16AE931B73C59D7E0C089C0,
]

# for m, h in zip(msgs, hashes):
#     hash = MD4(m)
#     print(hex(hash))

hash = MD4(b"a")
print(hex(hash))
