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

from c21 import MT19937


def undo_op(rnd, mask, shift, num_shifts, dir):
    last = reversed_rnd = rnd
    for i in range(num_shifts):
        last = eval(f"({last} {dir} {shift}) & {mask}")
        reversed_rnd ^= last
    return reversed_rnd


def untemper(rnd):
    rnd = undo_op(rnd, mask=0xFFFFFFFF, shift=18, num_shifts=1, dir=">>")
    rnd = undo_op(rnd, mask=0xEFC60000, shift=15, num_shifts=3, dir="<<")
    rnd = undo_op(rnd, mask=0x9D2C5680, shift=7, num_shifts=4, dir="<<")
    # what is the purpose of the 0xFFFFFFF mask? if we're shifting right, its a little redundant
    rnd = undo_op(rnd, mask=0xFFFFFFFF, shift=11, num_shifts=3, dir=">>")
    return rnd


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


def clone_RNG():
    gen = MT19937(123)
    rnds = []
    seeds = []
    for _ in range(624):
        rnd = gen.extract_numbers()
        rnds.append(rnd)
        seeds.append(untemper(rnd))

    new_gen = MT19937()
    new_gen.MT = seeds
    new_gen.idx = 0
    if new_gen.MT == gen.MT:
        print("internal state of the generators are the same!")


clone_RNG()

# mask = 0xFFFFFFFF
# test_vals = [204, 22372, 223721, 22372134, 2237213405, (1 << 32) - 1]
# for x in test_vals:

#     shift = 18
#     m = x ^ ((x >> shift) & mask)

#     last = reversed_x = m
#     for i in range(1):
#         last = (last >> shift) & mask
#         reversed_x ^= last

#     n = undo_op(m, mask, shift, num_shifts=1, dir=">>")
#     print_values({"m": m, "x": x, "final": reversed_x, "n": n})
