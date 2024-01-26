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


def encrypt_AES_CBC(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(message)


def write_to_file(contents, filename):
    f = open(filename, "wb")
    f.write(contents)
    f.close()


def CBC_encryption(message, iv, key):
    ciphertext = []
    bs = len(iv)
    blocks = [message[bs * i : (bs * (i + 1))] for i in range(len(message) // bs)]
    blocks[-1] = pad_block(blocks[-1], bs)
    prev_block = iv
    for block in blocks:
        xor_block = bytes(b1 ^ b2 for b1, b2 in zip(prev_block, block))
        enc_block = encrypt_AES_ECB(xor_block, key)
        ciphertext.append(enc_block)
        prev_block = enc_block
    return b"".join(ciphertext)


def CBC_decryption(message, iv, key):
    plaintext = []
    bs = len(iv)
    blocks = [message[bs * i : (bs * (i + 1))] for i in range(len(message) // bs)]
    prev = iv
    for block in blocks:
        dec_block = decrypt_AES_ECB(block, key)
        xored = bytes(b1 ^ b2 for b1, b2 in zip(dec_block, prev))
        plaintext.append(xored)
        prev = block
    return b"".join(plaintext)


key = "YELLOW SUBMARINE"
key_b = bytes(key, encoding="utf-8")
iv_b = bytes(16)

# f = open("c7_decrypted.txt", "rb")
# decrypted_b = f.read()
# check = encrypt_AES_CBC(decrypted_b, key_b, iv_b)
# cipher_text = CBC_encryption(decrypted_b, iv_b, key_b)
# print("encryption by CBC result:", check == cipher_text)

# plain_text = CBC_decryption(cipher_text, iv_b, key_b)
# print("decryption by CBC result:", plain_text == decrypted_b)

f = open("c10.txt", "r")
decrypted_b = base64.b64decode(f.read())
plain_text = CBC_decryption(decrypted_b, iv_b, key_b)
print(plain_text)
