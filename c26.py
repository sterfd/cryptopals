# Set 4 Challenge 26
# CTR bitflipping

"""There are people in the world that believe that CTR resists bit flipping attacks 
    of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier (C16) to use CTR mode instead of CBC mode. 
Inject an "admin=true" token."""

import random
from Crypto.Cipher import AES
from cryptopals_functions import encrypt_CTR, decrypt_CTR


class CBC_Admin:
    def __init__(self):
        self.key = random.randbytes(16)

    def encrypt_text(self, plaintext: bytes):
        head = b"comment1=cooking%20MCs;userdata="
        tail = b";comment2=%20like%20a%20pound%20of%20bacon"
        full_message = head + plaintext + tail
        full_quoted = full_message.replace(b"=", b'"="').replace(b";", b'";"')
        return encrypt_CTR(full_quoted, 0, self.key)

    def is_admin(self, ciphertext: bytes):
        plaintext = decrypt_CTR(ciphertext, 0, self.key)
        content_split = plaintext.split(b";")
        for chunk in content_split:
            if chunk == b'"admin=true"':
                return True
        return False


hello = CBC_Admin()
ct_to_48 = hello.encrypt_text(b"0" * 2 + b";admin")[:48]
ct_from_49 = bytearray(hello.encrypt_text(b"0" * 8 + b"=true;"))[48:]

hello.is_admin(ct_to_48)
hello.is_admin(ct_from_49)
hello.is_admin(ct_to_48 + ct_from_49)
for i in range(256):
    ct_from_49[0] = i
    concat = ct_to_48 + bytes(ct_from_49)
    if hello.is_admin(concat):
        print("ADMIN", i)
        break
