# # Set 3 Challenge 21
# Implement the MT19937 Mersenne Twister RNG
# You can get the psuedocode for this from Wikipedia.

# If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()";
# don't use rand(). Write the RNG yourself.

# mersenne prime is 1 less than a power of 2 - 3, 7, 31

w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18

MT_state = [None for i in range(n)]
idx = n + 1
lower_mask = (1 << r) - 1
upper_mask = ~(lower_mask) & ((1 << w) - 1)


def print_values(variables):
    max_name_length = max(len(name) for name in variables.keys())
    format_string = f"{{:<{max_name_length}}} | {{:>12}} | {{:>12}} | {{:>36}}"
    print(format_string.format("Variable", "Base 10", "Hex", "Binary"))
    for name, value in variables.items():
        print(format_string.format(name, value, hex(value), bin(value)))


print_values({"lower_mask": lower_mask, "upper_mask": upper_mask})
