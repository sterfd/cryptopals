# Set 2 Challenge 11

# An ECB/CBC detection oracle

# Now that you have ECB and CBC working:

# Write a function to generate a random AES key; that's just 16 random bytes.

# Write a function that encrypts data under an unknown key
#   --- that is, a function that generates a random key and encrypts under it.

# The function should look like:

# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]
# Under the hood, have the function append 5-10 bytes (count chosen randomly)
#   before the plaintext and 5-10 bytes after the plaintext.

# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
#   (just use random IVs each time for CBC). Use rand(2) to decide which to use.

# Detect the block cipher mode the function is using each time.
#   You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC,
#       tells you which one is happening.

import random
from c10 import CBC_encryption, encrypt_AES_ECB


def encryption_oracle(message, key_len):
    key = random.randbytes(key_len)
    pre_message = random.randbytes(random.randint(5, 10))
    post_message = random.randbytes(random.randint(5, 10))
    enc_mode = random.choice(["ecb", "cbc"])

    if enc_mode == "ecb":
        return encrypt_AES_ECB(pre_message + message + post_message, key)
    # cbc otherwise
    iv = random.randbytes(key_len)
    return CBC_encryption(pre_message + message + post_message, key, iv)


f = open("c7_decrypted.txt", "r")
plaintext = f.read()
plaintext_b = bytes(plaintext, encoding="utf-8")

print(encryption_oracle(plaintext_b, 16))
