def round1(a, b, c, d):
    X = [0] * 16
    mask = 0xFFFFFFFF

    def lrotate(bits, amount):
        return ((bits << amount) | (bits >> (32 - amount))) & mask

    def f(x, y, z):
        return (x & y) | (~x & z)  # xy v (-x)z - if x then y else z

    def r1_op(A, B, C, D, I, S):

        return lrotate((A + f(B, C, D) + X[I]) & mask, S)

    for x in range(4):
        a = r1_op(a, b, c, d, x * 4, 3)
        d = r1_op(d, a, b, c, x * 4 + 1, 7)
        c = r1_op(c, d, a, b, x * 4 + 2, 11)
        b = r1_op(b, c, d, a, x * 4 + 3, 19)
        # print("round1 group4", a, b, c, d)
        return a, b, c, d


def x(A, B, C, D):
    def left_rotate(bits, amount):
        return (bits << amount) | (bits >> (32 - amount))

    _F = lambda x, y, z: ((x & y) | (~x & z))
    X = [0] * 16
    for i in range(16):
        k = i
        if i % 4 == 0:
            # if i == 0:
            #     print("0", A, self._F(B, C, D), X[0])
            A = left_rotate((A + _F(B, C, D) + X[k]) & 0xFFFFFFFF, 3)
        elif i % 4 == 1:
            D = left_rotate((D + _F(A, B, C) + X[k]) & 0xFFFFFFFF, 7)
        elif i % 4 == 2:
            C = left_rotate((C + _F(D, A, B) + X[k]) & 0xFFFFFFFF, 11)
        elif i % 4 == 3:
            B = left_rotate((B + _F(C, D, A) + X[k]) & 0xFFFFFFFF, 19)
        # if (i + 1) % 4 == 0:
        #     print("round1, group of 4", A, B, C, D)
        if i == 3:
            return A & 0xFFFFFFFF, B & 0xFFFFFFFF, C & 0xFFFFFFFF, D & 0xFFFFFFFF


a, b, c, d = 13458, 22846, 32346, 44782
m, n, o, p = x(a, b, c, d)
r, s, t, u = round1(a, b, c, d)

print(m == r, n == s, o == t, p == u)
print(n, s)
print(int.bit_length(5135253111979))
print(int.bit_length(0xFFFFFFFF))
