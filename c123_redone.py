import base64

# decoded_bytes = bytes.fromhex(hex_string)
# encoded_64 = base64.b64encode(decoded_bytes)

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


def hp_freq_generation():
    from collections import defaultdict

    hp_freq = defaultdict(int)
    letter_perc = {}
    f = open("hp1.txt", "r")
    for ch in f.read():
        if ch.isalpha():
            hp_freq[ch.lower()] += 1
        elif ch == " ":
            hp_freq[ch] += 1
    total_letters = sum(hp_freq.values())
    for ch in hp_freq.keys():
        letter_perc[ch] = int(hp_freq[ch] / total_letters * 10000) / 10000

    sorted_dict = sorted(letter_perc, key=lambda x: letter_perc[x], reverse=True)
    for ch in sorted_dict:
        print(ch, letter_perc[ch])


def xor_equal_len(entry1, entry2):
    dec_e1, dec_e2 = bytes.fromhex(entry1), bytes.fromhex(entry2)
    xored_bytes = bytes(a ^ b for a, b in zip(dec_e1, dec_e2))
    return bytes.hex(xored_bytes)


def xor_key(entry, key):
    en_message = bytes.fromhex(entry)
    decoded_bytes = bytes(a ^ key for a in en_message)

    # KL_divergence scoring
    # score = frequency_kl_scoring(decoded_bytes)
    # if len(best_scores) > 10:
    #     heapq.heappushpop(best_scores, (-score, key, decoded_bytes))
    # else:
    #     heapq.heappush(best_scores, (-score, key, decoded_bytes))

    # score = space_scoring(decoded_bytes)
    # if score > 0:
    #     print(score, key, decoded_bytes)

    # score = vowel_scoring(decoded_bytes)
    # if len(best_scores) > 4:
    #     heapq.heappushpop(best_scores, (score, key, decoded_bytes))
    # else:
    #     heapq.heappush(best_scores, (score, key, decoded_bytes))


def space_scoring(decoded):
    score = int(decoded.count(ord(" ")) / len(decoded) * 1000) / 1000
    return score


def vowel_scoring(decoded):
    vowels = [ord(v) for v in ["a", "e", "i", "o", "u", " "]]
    score = 0
    for ch in bytes(decoded):
        if ch in vowels:
            score += 1
    return int(score / len(decoded) * 1000) / 1000


def frequency_kl_scoring(decoded):
    """
    KL divergence, aka relative entropy:
    D_kl(p(x) || q(x)) = sum_for_all_x = p(x)ln(p(x)/q(x)) where p and q are probability distributions
    score of 0 means no entropy - same distribution
    """
    from collections import Counter
    import math

    letter_count = Counter(str(decoded).lower())
    message_len = len(decoded)
    mess_freq = {
        ch: int(letter_count[ch] / message_len * 1000) / 1000 for ch in letter_count
    }
    KL_div_score = 0
    for ch in hp_freq:
        if ch in letter_count:
            KL_div_score += hp_freq[ch] * math.log(hp_freq[ch] / mess_freq[ch])
        else:
            KL_div_score += hp_freq[ch] * math.log(hp_freq[ch] / (10**-10))
    return KL_div_score


import heapq

best_scores = []
en_message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

for i in range(48, 123):
    xor_key(en_message, i)

for scores, key, message in sorted(best_scores):
    print(-scores, key, message)


# vowel scoring
# for scores, key, message in sorted(best_scores, reverse=True):
#     print(scores, key, message)
