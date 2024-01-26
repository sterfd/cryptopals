# Set 2 Challenge 10

# Implement CBC mode
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
# despite the fact that a block cipher natively only transforms individual blocks.

# In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

# The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block"
# called the initialization vector, or IV.

# Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
# (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

# The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

# Don't cheat.
# Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
# What's the point of even doing this stuff if you aren't going to learn from it?

import base64
from Crypto.Cipher import AES
from c9 import pad_block


def decrypt_AES_ECB(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(message)


def encrypt_AES_ECB(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)


def write_to_file(contents, filename):
    f = open(filename, "wb")
    f.write(contents)
    f.close()


def CBC_encryption(message, iv):
    # chunk into blocks
    # add padding if needed

    pass


def CBC_encrypt_block(block, key):
    pass


# overall function to build cipher
# have a encrypted array = []
# takes in bytes to encrypt
# breaks it up into blocks of keysize length chunks
# sends each block off to helper function to ECB and return ecb block
#

# helper function to deal with each block
#


key = "YELLOW SUBMARINE"  # 16 key length
key_b = bytes(key, encoding="utf-8")
iv_b = bytes(16)


# example encryption
# f = open("c7_decrypted.txt", "rb")
# decrypted_b = f.read()
# print(len(decrypted_b))
# encrypted_ECB = encrypt_AES_ECB(decrypted_b, key_b)
# encrypted_b64 = base64.b64encode(encrypted_ECB)
# print(encrypted_b64)
