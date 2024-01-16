# Set 1 Challenge 6

# Break repeating-key XOR

# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

# Decrypt it.

# Here's how:

import base64
import heapq
from s1_c123_redone import vowel_scoring


def calc_hamming_distance(byte1, byte2):
    distance = sum((bin(b1 ^ b2).count("1") for b1, b2 in zip(byte1, byte2)))
    return distance


def find_keysize(text_bytes):
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

    return sorted(keysize_scores, reverse=True)[0][1]


def keysize_blocks(text, keysize):
    blocks = [[] for _ in range(keysize)]
    idx = 0
    for byte in text:
        blocks[idx % keysize].append(byte)
        idx += 1
    return blocks


def xor_key(entry, key):
    decoded_bytes = bytes(a ^ key for a in entry)
    return (vowel_scoring(decoded_bytes), decoded_bytes)


def break_xor(text_bytes, keysize):
    blocks = keysize_blocks(text_bytes, keysize)
    resulting_blocks = []

    for idx, block in enumerate(blocks):
        best_score = 0
        best_block = None
        for i in range(0, 255):
            score, decoded_bytes = xor_key(block, i)
            if score > best_score:
                best_score = score
                best_block = decoded_bytes
        resulting_blocks.append(best_block)

    final_text = []
    for i in range(len(text_bytes)):
        final_text.append(chr(resulting_blocks[i % keysize][i // keysize]))

    return "".join(final_text)


f = open("c6.txt", "r")
from_text = f.read()
text_bytes = base64.b64decode(from_text)

keysize = find_keysize(text_bytes)
print(break_xor(text_bytes, keysize))
