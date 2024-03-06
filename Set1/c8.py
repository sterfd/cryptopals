# Set 1 Challenge 8

# Detect AES in ECB mode
# In this file are a bunch of hex-encoded ciphertexts.

# One of them has been encrypted with ECB.

# Detect it.


# Remember that the problem with ECB is that it is stateless and deterministic;
# the same 16 byte plaintext block will always produce the same 16 byte ciphertext.


def text_to_blocks(text, blocksize):
    blocks = [
        text[x * blocksize : (x * blocksize) + blocksize]
        for x in range(len(text) // blocksize)
    ]
    return blocks


def detect_ECB(ciphertext, blocksize):
    blocks = text_to_blocks(ciphertext, blocksize)
    num_blocks = len(blocks)
    unique_blocks = len(set(blocks))
    if num_blocks != unique_blocks:
        return True
    return False


f = open("c8.txt", "r")
blocksize = 16
ciphertexts = [bytes.fromhex(text.strip()) for text in f]
# 204 of them.... D:

# for i, text in enumerate(ciphertexts):
#     if detect_ECB(text, blocksize):
#         print("Line {} has repeated chunks of bytes".format(i))
