# Set 1 Challenge 8

# Detect AES in ECB mode
# In this file are a bunch of hex-encoded ciphertexts.

# One of them has been encrypted with ECB.

# Detect it.

# Remember that the problem with ECB is that it is stateless and deterministic;
# the same 16 byte plaintext block will always produce the same 16 byte ciphertext.


f = open("c8.txt", "r")
ciphertexts = [bytes.fromhex(text) for text in f.readlines()]
print(len(ciphertexts))
# 204 of them.... D:
