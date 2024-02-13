# Set 2 - Challenge 16

# CBC bitflipping attacks
# Generate a random AES key.

# Combine your padding code and CBC code to write two functions.

# The first function should take an arbitrary input string, prepend the string:

# "comment1=cooking%20MCs;userdata="
# .. and append the string:

# ";comment2=%20like%20a%20pound%20of%20bacon"
# The function should quote out the ";" and "=" characters.

# The function should then pad out the input to the 16-byte
# AES block length and encrypt it under the random AES key.

# The second function should decrypt the string and look for the characters ";admin=true;"
# (or, equivalently, decrypt, split the string on ";",
# convert each resulting string into 2-tuples, and look for the "admin" tuple).

# Return true or false based on whether the string exists.

# If you've written the first function properly,
# it should not be possible to provide user input to it that will generate the string the second function is looking for.
# We'll have to break the crypto to do that.

# Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
# - Completely scrambles the block the error occurs in
# - Produces the identical 1-bit error(/edit) in the next ciphertext block.

# *** Stop and think for a second. ***
# Before you implement this attack, answer this question: why does CBC mode have this property?

from cryptopals_functions import encrypt_CBC, decrypt_CBC, fixed_xor
import random
from c15 import validate_pkcs_padding


class CBC_bitflip:
    def __init__(self):
        self.AES_key = random.randbytes(16)

    def encrypt_text(self, plaintext: bytes):
        head = b"comment1=cooking%20MCs;userdata="
        tail = b";comment2=%20like%20a%20pound%20of%20bacon"
        full_message = head + plaintext + tail
        full_quoted = full_message.replace(b"=", b'"="').replace(b";", b'";"')
        return encrypt_CBC(full_quoted, bytes(16), self.AES_key)

    def is_admin(self, ciphertext: bytes):
        plaintext = decrypt_CBC(ciphertext, bytes(16), self.AES_key)
        plaintext_unpadded = validate_pkcs_padding(plaintext, 16)
        pt_blocks = [
            plaintext_unpadded[i * 16 : (i + 1) * 16]
            for i in range(len(plaintext_unpadded) // 16 + 1)
        ]
        print(pt_blocks[3:5])
        content_split = plaintext_unpadded.split(b";")
        for chunk in content_split:
            if chunk == b'"admin=true"':
                return True
        return False


oracle = CBC_bitflip()
message_admin_end = bytes(17) + b";admin=true;"
ct_admin_end = oracle.encrypt_text(message_admin_end)
ct_admin_blocks = [ct_admin_end[16 * i : (i + 1) * 16] for i in range(4)]

message_true_start = bytes(17) + b';admin"true;' + bytes(10)
ct_true_start = oracle.encrypt_text(message_true_start)
ct_true_blocks = [
    ct_true_start[16 * i : (i + 1) * 16] for i in range(4, len(ct_true_start) // 16)
]

concat_blocks = b"".join(ct_admin_blocks + ct_true_blocks)
concat_blocks = [b for b in concat_blocks]
for i in range(256):
    concat_blocks[47] = i
    print(i)
    pt_concat = oracle.is_admin(bytes(concat_blocks))
    if pt_concat:
        print("YES")
        break
