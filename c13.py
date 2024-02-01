# Set 2 Challenge 13
# ECB cut-and-paste

# Write a k=v parsing routine, as if for a structured cookie. The routine should take:
# foo=bar&baz=qux&zap=zazzle
# ... and produce:
# {
#   foo: 'bar',
#   baz: 'qux',
#   zap: 'zazzle'
# }
# (you know, the object; I don't care if you convert it to JSON).

# Now write a function that encodes a user profile in that format, given an email address. You should have something like:
# profile_for("foo@bar.com")
# ... and it should produce:

# {
#   email: 'foo@bar.com',
#   uid: 10,
#   role: 'user'
# }
# ... encoded as:

# email=foo@bar.com&uid=10&role=user
# Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

# Now, two more easy functions. Generate a random AES key, then:

# Encrypt the encoded user profile under the key; "provide" that to the "attacker".
# Decrypt the encoded user profile and parse it.
# Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

import random
from cryptopals_functions import encrypt_AES_ECB, decrypt_AES_ECB


class Profiles:
    def __init__(self):
        self.key = random.randbytes(16)

    def profile_for(self, email_add):
        for i, b in enumerate(email_add):
            if b == 38 or b == 61:
                email_add[i] = 95
        return b"email=" + email_add + b"&uid=10&role=user"

    def encrypt_profile_ECB(self, email):
        profile_encoding = self.profile_for(email)
        return encrypt_AES_ECB(profile_encoding, self.key)

    def profile_parsing(self, p_bytes):
        p_enc = p_bytes.decode(encoding="utf-8")
        p_params = p_enc.split("&")
        p_dict = {k: v for p in p_params for k, v in [p.split("=")]}
        return p_dict

    def get_role(self, ciphertext):
        profile_b = decrypt_AES_ECB(ciphertext, self.key)
        profile = self.profile_parsing(profile_b)
        return profile["role"]


def find_enc_padding():
    end_user = b"@user"
    prev_len = len(oracle.encrypt_profile_ECB(end_user))
    for i in range(1, 16):
        email = bytes([0]) * i
        enc_profile = oracle.encrypt_profile_ECB(email)
        if len(enc_profile) > prev_len:
            return i - 1


oracle = Profiles()
profile_padlen = find_enc_padding()
ciphertext_end_user_block = oracle.encrypt_profile_ECB(
    bytes([0]) * (profile_padlen + 4)
)
admin_email = bytes([0]) * (profile_padlen + 1) + b"admin" + bytes([11]) * 11
ciphertext_admin_padded = oracle.encrypt_profile_ECB(admin_email)
ciphertext_changed_role = (
    ciphertext_end_user_block[:-16] + ciphertext_admin_padded[16:32]
)
role = oracle.get_role(ciphertext_changed_role)
print(role)
