# Set 3 Challenge 18
# Implement CTR, the stream cipher mode

"""
The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
... decrypts to something approximating English in CTR mode, 
    which is an AES block cipher mode that turns AES into a stream cipher, 
    with the following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, 
    producing a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
CTR mode does not require padding; when you run out of plaintext, 
    you just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. 
    Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, 
    then use your CTR function to encrypt and decrypt other things.

***    
This is the only block cipher mode that matters in good code.
    Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, 
    because most of what we want to encrypt is better described as a stream than as a sequence of blocks. 
    Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms.
    Constructions like CTR are what he was talking about.
"""
import base64
from cryptopals_functions import encrypt_AES_ECB

ciphertext_b64 = (
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)
ciphertext = base64.b64decode(ciphertext_b64)
key = b"YELLOW SUBMARINE"
pt = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def decrypt_CTR(ct, nonce, key):
    pt = b""
    bs = len(key)
    for block in range(len(ct) // bs + 1):
        counter = nonce.to_bytes(length=bs // 2, byteorder="little") + block.to_bytes(
            length=bs // 2, byteorder="little"
        )
        keystream = encrypt_AES_ECB(counter, key)
        pt += bytes(k ^ c for k, c in zip(keystream, ct[block * bs : (block + 1) * bs]))
    return pt


def encrypt_CTR(pt, nonce, key):
    ct = b""
    bs = len(key)
    for block in range(len(pt) // bs + 1):
        counter = nonce.to_bytes(length=bs // 2, byteorder="little") + block.to_bytes(
            length=bs // 2, byteorder="little"
        )
        keystream = encrypt_AES_ECB(counter, key)
        ct += bytes(k ^ p for k, p in zip(keystream, pt[block * 16 : (block + 1) * 16]))
    return ct


# ct = base64.b64encode(encrypt_CTR(pt, 0, key))
# print(ct)
