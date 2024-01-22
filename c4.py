# Set 1 Challenge 4

# Detect single-character XOR
# One of the 60-character strings in this file has been encrypted by single-character XOR.

# Find it.

# (Your code from #3 should help.)

hp_freq = {
    "h": 0.0555,
    "a": 0.0655,
    "r": 0.0533,
    "y": 0.0212,
    " ": 0.1744,
    "p": 0.0136,
    "o": 0.0644,
    "t": 0.0715,
    "e": 0.0983,
    "n": 0.0537,
    "d": 0.0409,
    "s": 0.0485,
    "c": 0.0165,
    "b": 0.0131,
    "w": 0.0206,
    "l": 0.0359,
    "i": 0.0512,
    "v": 0.0071,
    "m": 0.0182,
    "u": 0.024,
    "f": 0.0168,
    "k": 0.0098,
    "x": 0.0009,
    "g": 0.0212,
    "j": 0.0009,
    "z": 0.0006,
    "q": 0.001,
}

from s1_c123_redone import frequency_kl_scoring


def xor_key(entry, key):
    en_message = bytes.fromhex(entry)
    decoded_bytes = bytes(a ^ key for a in en_message)

    # KL_divergence scoring
    score = frequency_kl_scoring(decoded_bytes)
    all_scores.append((score, key, decoded_bytes))


def test_message(message):
    for i in range(0, 255):
        xor_key(message, i)


all_scores = []
f = open("c4.txt", "r")
for line in f.readlines():
    test_message(line)

for score, key, decoded_bytes in sorted(all_scores, reverse=True):
    print(score, key, decoded_bytes)

print("\nThe decoded string is", min(all_scores)[2])

# vowels scoring didn't work
# KL_divergence and space scoring worked great
