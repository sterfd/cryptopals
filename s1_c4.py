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

from s1_c123_redone import frequency_kl_scoring, space_scoring, vowel_scoring
import heapq


def xor_key(entry, key):
    en_message = bytes.fromhex(entry)
    decoded_bytes = bytes(a ^ key for a in en_message)

    # KL_divergence scoring
    score = frequency_kl_scoring(decoded_bytes)

    # score = space_scoring(decoded_bytes)

    # score = vowel_scoring(decoded_bytes)
    if len(best_scores) > 10:
        heapq.heappushpop(best_scores, (-score, key, entry, decoded_bytes))
    else:
        heapq.heappush(best_scores, (-score, key, entry, decoded_bytes))


def test_message(message):
    for i in range(48, 123):
        xor_key(message, i)


best_scores = []
f = open("c4.txt", "r")
for line in f.readlines():
    test_message(line)

for score, key, _, decoded_bytes in sorted(best_scores, reverse=True):
    print(-score, key, decoded_bytes)


# vowels scoring didn't work
# KL_divergence and space scoring worked great
