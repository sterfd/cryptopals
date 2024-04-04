# Set 5 Challenge 35
# Implement DH with negotiated groups, and break with malicious "g" parameters

"""
A->B
Send "p", "g"
B->A
Send ACK
A->B
Send "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
Do the MITM attack again, but play with "g". What happens with:

    g = 1
    g = p
    g = p - 1
Write attacks for each.

When does this ever happen?
Honestly, not that often in real-world systems. 
    If you can mess with "g", chances are you can mess with something worse. 
        Most systems pre-agree on a static DH group. 
            But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
"""

from c34 import Sender, Recipient
from c33 import modexp
from c28 import SHA1
from cryptopals_functions import decrypt_CBC, encrypt_CBC
import random


def MITM_g(g):
    alice = Sender()
    P, G_alice, pk_alice = alice.open_connection()
    bob = Recipient(P, P, P)
    pk_bob = bob.send_pk()
    encrypted_msg_alice, iv_alice = alice.receive_connection(pk_bob)
    # hashed_ss = SHA1(bytes([0]))
    hashed_ss = SHA1(b"")
    AES_key = hashed_ss.to_bytes((hashed_ss.bit_length() + 7) // 8, "big")[:16]
    decrypted_msg = decrypt_CBC(encrypted_msg_alice, iv_alice, AES_key)
    print(decrypted_msg)

    encrypted_msg_bob, iv_bob = bob.receive_message(encrypted_msg_alice, iv_alice)
    print(alice.receive_message(encrypted_msg_bob, iv_bob))


MITM_g(1)
