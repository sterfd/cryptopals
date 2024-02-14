# Set 3 Challenge 17
# The CBC Padding Oracle

"""
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), 
    pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, 
    providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, 
    decrypt it, check its padding, and return true or false depending on whether the padding is valid.

***What you're doing here.***
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; 
    the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. 
    The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

    The fundamental insight behind this attack is that the byte 01h is valid padding, 
    and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

    02h in isolation is not valid padding.

    02h 02h is valid padding, but is much less likely to occur randomly than 01h.

    03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, 
    you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". 
    Padding oracles have nothing to do with the actual padding on a CBC plaintext. 
        It's an attack that targets a specific bit of code that handles decryption. 
            You can mount a padding oracle on any CBC block, whether it's padded or not."""
import random
from cryptopals_functions import encrypt_CBC, decrypt_CBC
from c15 import validate_pkcs_padding


class Oracle:
    def __init__(self):
        self.key = random.randbytes(16)
        self.message = random.choice(
            [
                b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
            ]
        )
        self.iv = bytes(16)

    def get_ciphertext(self):
        ciphertext = encrypt_CBC(self.message, self.iv, self.key)
        return ciphertext, self.iv

    def check_pad(self, ciphertext):
        pt = decrypt_CBC(ciphertext, self.iv, self.key)
        unpadded = validate_pkcs_padding(pt, len(self.key))
        if unpadded:
            return True
        return False


class CBC_attack:
    def __init__(self):
        self.oracle = Oracle()
        self.ct, self.iv = self.oracle.get_ciphertext()
        self.ciphertext = self.iv + self.ct

    def verify_pad_number(self, block, idx):
        block[idx - 1] = (block[idx - 1] + 1) % 256
        check_ct = self.oracle.check_pad(block)
        block[idx - 1] = (block[idx - 1] - 1) % 256
        if check_ct:
            return True
        return False

    def decrypt_block(self, ct_idx):
        decrypted = bytearray(16)
        block = bytearray(self.ciphertext[ct_idx : ct_idx + 32])
        for pad_len in range(1, 17):
            pad_idx = 16 - pad_len
            for i in range(256):
                block[pad_idx] = i
                if self.oracle.check_pad(bytes(block)):
                    if pad_idx > 0 and not self.verify_pad_number(block, pad_idx):
                        continue
                    decrypted[pad_idx] = pad_len ^ i
                    block[pad_idx] = decrypted[pad_idx] ^ (pad_len + 1)
                    for rest in range(pad_idx + 1, 16):
                        block[rest] = decrypted[rest] ^ (pad_len + 1)
                    break
        return bytes(
            d ^ p for d, p in zip(decrypted, self.ciphertext[ct_idx : ct_idx + 16])
        )

    def pad_attack(self):
        plaintext = b""
        for block_idx in range(len(self.ciphertext) // 16 - 1):
            pt_block = self.decrypt_block(block_idx * 16)
            plaintext += pt_block
        return plaintext


import base64

uhhh_first_try = CBC_attack()
pt = uhhh_first_try.pad_attack()
print(base64.b64decode(pt))


"""
                    last block-ciphertext
                        v   aes-ecb with KEY
prev block (rand)   last block-decrypted        
    13                  x
            XOR
            v   
            /x01    last block-plaintext (not seen)

                    last block -decrypted = 13 ^ /x01
            XOR with prev block
            v
            PLAINTEXT OHHHH
"""
