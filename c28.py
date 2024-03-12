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


class SHA1:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # all vars are unsigned 32-bit quantities - wrap modulo 2**32 wehn calc
    # except
    #       ml - message len, 64-bit quantity
    #       hh - message digest, 160-bit quantity
    # all constants are big endian - most significant byte stored left

    def __init__(self, message: bytes):
        self.message = bytearray(message)

    def preprocess(self):
        # add an x byte to the message, then 0 bytes until ml is 56 mod 64, then ml (8 bytes)
        self.message += bytes([128])
        add_zeros = (56 - (len(self.message) % 64) + 64) % 64
        self.message += bytes(add_zeros)
        self.message += len(self.message).to_bytes(8, byteorder="big")

    def left_rotate(self, chunk):
        pass

    def chunky_time(self):  # break into 64-byte chunks
        """
        Process the message in successive 512-bit/64-byte chunks:
        break message into 512-bit/64-byte chunks
        for each chunk
            break chunk into sixteen 32-bit/8-byte big-endian words w[i], 0 ≤ i ≤ 15

            Message schedule: extend the sixteen 32-bit/8-byte words into eighty 32-bit words:
            for i from 16 to 79
                Note 3: SHA-0 differs by not having this leftrotate.
                w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1"""
        pass


def print_values(variables):
    max_name_length = max(len(name) for name in variables.keys())
    format_string = f"{{:<{max_name_length}}} | {{:>12}} | {{:>40}} | {{:>5}}| {{:>5}}"
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


x = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
hexvals = {f"hexval {i}": a for i, a in enumerate(x)}
# print_values(hexvals)


message = b"heyy how are you my name is stephanie. i am really hungry"
# print("message len", len(message), bin(len(message)))
# print(bin((len(message)) << 5))
# print(0x80, bin(0x80), hex(0x80), bytes([128]))

x = SHA1(message)
x.preprocess()

# print(len(message))
# message += bytes([128])
# print(len(message))
