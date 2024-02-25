# Set 3 Challenge 23
# Clone an MT19937 RNG from its output

"""The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. 
    By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected 
    to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function 
    that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. 
    There are two kinds of operations in the temper transform each applied twice; 
        one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. 
            So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, 
    untemper each of them to recreate the state of the generator, 
        and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

**Stop and think for a second.**
    How would you modify MT19937 to make this attack hard? 
    What would happen if you subjected each tempered output to a cryptographic hash?
    
# """

#         y = self.MT[self.idx]
#         y = y ^ ((y >> self.u) & self.d)  # y xor (y // 2**11 & 32bit window)
#         y = y ^ ((y << self.s) & self.b)
#         # y xor (y * 2 **7) & random 13bit window, 32 long)
#         y = y ^ ((y << self.t) & self.c)
#         # y xor (y * 2 ** 15 & random 11bit window, 32 long)
#         y = y ^ (y >> self.l)  # y xor (y // 2** 18)

#         self.idx += 1
#         return y & self.wmask


def untemper(rnd):
    rnd = rnd ^ (rnd >> 18)
    rnd = rnd ^ ((rnd << 15) & 0xEFC60000)


#   y = y ^ ((y << self.s) & self.b)   7, 0x9D2C5680


#   y = y ^ ((y >> self.u) & self.d)  # y xor (y // 2**11 & 32bit window)


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


mask = 0xEFC60000
x = 20425
x = 20425
y = 2042589
z = 2237213405
m = x ^ ((x << 18) & mask)
# y = y ^ (y >> self.l)
print_values(
    {
        "x": x,
        "x << l": x << 15,
        "x << l & mask": (x << 15) & mask,
        "x ^(x >> l) & 0x": m,
        "0": 0,
        "0xEFC60000": mask,
        "m": m,
        "m << l": m << 15,
        "m << l & 0x": m << 15 & mask,
        "m ^((m<<l))": m ^ ((m << 15) & mask),
    }
)
