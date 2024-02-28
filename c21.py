# # Set 3 Challenge 21
# Implement the MT19937 Mersenne Twister RNG
# You can get the psuedocode for this from Wikipedia.

# If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()";
# don't use rand(). Write the RNG yourself.


# mersenne prime is 1 less than a power of 2 - 3, 7, 31
class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253
    wmask = (1 << w) - 1  # -> have w-bit window (bin = w number of 1s)
    lower_mask = (1 << r) - 1  # 31 bit window
    # x << y - > defined as x with bits shifted to left by y places
    #   also is = x * 2**y
    # (1<<y) -> 1(0 * y) in binary
    # so (1 << y) - 1 -> y number of 1 bits
    upper_mask = 1 << r  # ~(lower_mask) & ((1 << w) - 1) -> bin 1 0*31
    # x >> y -> x with bits shifted to right by y places
    # x // 2**y

    def __init__(self, seed=5489):
        self.idx = self.n
        self.MT = [0] * self.n
        self.MT[0] = seed
        for i in range(1, self.n):  # loop over every int
            self.MT[i] = self.wmask & (
                self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i
            )
            # 32 bits of ( f * (mt[i-1] ^ (mt[i-1] // 30)) + i)

    def new_seed(self, seed):
        self.idx = self.n
        self.MT = [0] * self.n
        self.MT[0] = seed
        for i in range(1, self.n):  # loop over every int
            self.MT[i] = self.wmask & (
                self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i
            )
            # 32 bits of ( f * (mt[i-1] ^ (mt[i-1] // 30)) + i)

    def twist(self):  # generate next n values from series x_i
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (
                self.MT[(i + 1) % self.n] & self.lower_mask
            )
            # the 32nd bit of self.MT[i] and the first 31 bits of self.MT[i+1]
            xA = x >> 1  # xA = x // 2
            xA = xA ^ self.a if (x % 2 != 0) else xA  # if x ends in 1, xor with a
            self.MT[i] = (
                self.MT[(i + self.m) % self.n] ^ xA
            )  # self.MT[i] = self.MT[i+397] ^ xA
        self.idx = 0  # every time generator is init with seed, reset seed

    def extract_numbers(self):
        if self.idx >= self.n:
            self.twist()
        y = self.MT[self.idx]
        y = y ^ ((y >> self.u) & self.d)
        # y xor (y // 2**11 & 0xFFFFFFFF 32bit window)
        y = y ^ ((y << self.s) & self.b)
        # y xor (y * 2 **7) & 0x9D2C5680 random 13bit window, 32 long)
        y = y ^ ((y << self.t) & self.c)
        # y xor (y * 2 ** 15 & 0xEFC60000 random 11bit window, 32 long)
        y = y ^ (y >> self.l)  # y xor (y // 2** 18)

        self.idx += 1
        return y & self.wmask

    def print_values(variables):
        max_name_length = max(len(name) for name in variables.keys())
        format_string = (
            f"{{:<{max_name_length}}} | {{:>12}} | {{:>36}} | {{:>5}}| {{:>5}}"
        )
        print(format_string.format("Variable", "Base 10", "Binary", "Bin1s", "BinLen"))
        for name, value in variables.items():
            print(
                format_string.format(
                    name,
                    value,
                    bin(value),
                    bin(value).count("1"),
                    len(bin(value)) - 2,
                )
            )

    # print_values(
    #     {
    #         "20 >> 1": 20 >> 1,
    #         "d": d,
    #         "b": b,
    #         "c": c,
    #     }
    # )


# rng = MT19937(123)
# print(rng.extract_numbers())
# print(rng.extract_numbers())
# print(rng.extract_numbers())
# rng.new_seed(123)
# print(rng.extract_numbers())
# print(rng.extract_numbers())
# print(rng.extract_numbers())
