# Set 5 Challenge 34
# Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

"""
Use the code you just worked out to build a protocol and an "echo" bot. 
    You don't actually have to do the network part of this if you don't want; 
        just simulate that. The protocol is:

A->B
Send "p", "g", "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
(In other words, derive an AES key from DH with SHA1, use it in both directions, 
    and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:

A->M
Send "p", "g", "A"
M->B
Send "p", "g", "p"
B->M
Send "B"
M->A
Send "p"
A->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
M->B
Relay that to B
B->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
M->A
Relay that to A
M should be able to decrypt the messages. "A" and "B" in the protocol --- 
    the public keys, over the wire --- have been swapped out with "p".
     Do the DH math on this quickly to see what that does to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work; 
    you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. 
        But do the parameter injection attack; it's going to come up again.
"""
from c28 import SHA1
from c33 import modexp
from cryptopals_functions import encrypt_CBC, decrypt_CBC
import random


class Sender:
    def __init__(self):
        self.P = """0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff"""
        self.P = int(self.P.replace("\n", ""), base=16)
        self.G = 2
        self.secret_key = random.randint(0, self.P - 1)
        self.public_key = modexp(self.G, self.secret_key, self.P)
        self.message = self.get_message()

    def get_message(self):
        with open("secrets.txt", "rb") as f:
            lines = f.readlines()
            random_line = random.choice(lines).strip()
            return random_line

    def open_connection(self):
        return self.P, self.G, self.public_key

    def receive_connection(self, p_key):
        s_int = modexp(p_key, self.secret_key, self.P)
        self.shared_secret = s_int.to_bytes((s_int.bit_length() + 7) // 8, "big")[:16]
        iv = random.randbytes(16)
        key = bytes.fromhex(hex(SHA1(self.shared_secret))[2:])[:16]
        return encrypt_CBC(self.message, iv, key), iv

    def receive_message(self, msg, iv):
        hashed_int = SHA1(self.shared_secret)
        key = hashed_int.to_bytes((hashed_int.bit_length() + 7) // 8, "big")[:16]
        decrypted_msg = decrypt_CBC(msg, iv, key)
        if decrypted_msg == self.message:
            return b"Confirmed message yay: " + decrypted_msg
        else:
            return "Damn it didn't work"


class Recipient:
    def __init__(self, P, G, partner_pk):
        self.P = P
        self.G = G
        self.partner_pk = partner_pk
        self.secret_key = random.randint(0, self.P - 1)
        self.public_key = modexp(self.G, self.secret_key, self.P)

    def send_pk(self):
        return self.public_key

    def receive_message(self, encrypted_msg, iv):
        s_int = modexp(self.partner_pk, self.secret_key, self.P)
        shared_secret = s_int.to_bytes((s_int.bit_length() + 7) // 8, "big")[:16]
        AES_key = bytes.fromhex(hex(SHA1(shared_secret))[2:])[:16]
        dec_msg = decrypt_CBC(encrypted_msg, iv, AES_key)
        new_iv = random.randbytes(16)
        return encrypt_CBC(dec_msg, iv=new_iv, key=AES_key), new_iv


def bob_talk_to_alice():
    alice = Sender()
    # open connection from alice to bob
    P, G, pk_alice = alice.open_connection()
    bob = Recipient(P, G, pk_alice)

    # send bob's pk to alice for sharing messages
    encrypted_msg, iv = alice.receive_connection(bob.send_pk())

    # received message from alice, bob decrypt then encrypt with new iv
    bobs_msg, new_iv = bob.receive_message(encrypted_msg, iv)

    # return alices message with bobs encryption to validate connection
    print(alice.receive_message(bobs_msg, new_iv))


def MITM():

    alice = Sender()
    P, G, pk_alice = alice.open_connection()
    bob = Recipient(P, G, P)
    pk_bob = bob.send_pk()
    encrypted_msg_alice, iv_alice = alice.receive_connection(P)

    encrypted_msg_bob, iv_bob = bob.receive_message(encrypted_msg_alice, iv_alice)
    print(alice.receive_message(encrypted_msg_bob, iv_bob))

    shared_secret = b""
    hashed_ss = SHA1(shared_secret)
    AES_key = hashed_ss.to_bytes((hashed_ss.bit_length() + 7) // 8, "big")[:16]
    decrypted_msg = decrypt_CBC(encrypted_msg_alice, iv_alice, AES_key)
    print("did i unlock alice? ", decrypted_msg)


# bob_talk_to_alice()
MITM()
