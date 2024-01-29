# Set 1 Challenge 6

# Break repeating-key XOR

# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

# Decrypt it.

# Here's how:

import base64
import heapq


def calc_hamming_distance(byte1, byte2):
    distance = sum((bin(b1 ^ b2).count("1") for b1, b2 in zip(byte1, byte2)))
    return distance


m1 = b"this is a test"
m2 = b"wokka wokka!!!"
# print(calc_hamming_distance(m1, m2))


def find_keysize():
    f = open("c6.txt", "r")
    from_text = f.read()
    text_bytes = base64.b64decode(from_text)
    keysize_scores = []

    for keysize in range(2, 41):
        distances = []
        for i in range(0, len(text_bytes), keysize):
            first = text_bytes[i : keysize + i]
            second = text_bytes[keysize + i : keysize * 2 + i]
            distances.append(calc_hamming_distance(first, second) / keysize)
        avg_distance = sum(distances) / len(distances)

        if len(keysize_scores) > 4:
            heapq.heappushpop(keysize_scores, (-avg_distance, keysize))
        else:
            heapq.heappush(keysize_scores, (-avg_distance, keysize))

    for distances, keysize in sorted(keysize_scores, reverse=True):
        print(keysize, -distances)


# find_keysize()

"""
find_keysize() gave us:
    29 2.7110344827586204
    38 3.1004155124653736
    40 3.131944444444446
    25 3.138275862068967
    33 3.139462809917356
"""

from s1_c123_redone import frequency_kl_scoring, space_scoring, vowel_scoring


def keysize_blocks(text, keysize):
    blocks = [[] for _ in range(keysize)]
    idx = 0
    for byte in text:
        blocks[idx % keysize].append(byte)
        idx += 1
    return blocks


def break_xor(keysize):
    def xor_key(entry, key):
        nonlocal best_score
        decoded_bytes = bytes(a ^ key for a in entry)

        # score = frequency_kl_scoring(decoded_bytes)
        # # if score < best_score[0]:
        # #     best_score = (score, decoded_bytes)

        score = vowel_scoring(decoded_bytes)
        if len(best_score) > 2:
            heapq.heappushpop(best_score, (score, decoded_bytes))
        else:
            heapq.heappush(best_score, (score, decoded_bytes))
        # if score > best_score[0]:
        #     best_score = (score, decoded_bytes)

    f = open("c6.txt", "r")
    text = f.read()
    text_bytes = base64.b64decode(text)

    blocks = keysize_blocks(text_bytes, keysize)
    resulting_blocks = []
    for idx, block in enumerate(blocks):
        best_score = []
        # best_score = (0, "asdf")
        for i in range(0, 255):
            xor_key(block, i)
        print("\n\nblock", idx)
        for score, decoded in best_score:
            print(score, decoded)
        resulting_blocks.append(best_score[0][1])
    # print("result\n\n", resulting_blocks)

    final_text = []
    for i in range(len(text_bytes)):
        final_text.append(chr(resulting_blocks[i % keysize][i // keysize]))
    print("\n\nFINAL RESULT\n\n", "".join(final_text))


keysizes = [29]  # 29, 38, 40, 25, 33
for ks in keysizes:
    print(ks)
    break_xor(ks)
