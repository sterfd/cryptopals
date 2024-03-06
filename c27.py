# Set 4 Challenge 27
# Recover the key from CBC with IV=Key

"""
Take your code from the CBC exercise (16) and modify it so that it 
    repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the 
    sender and the receiver have to know the key already, 
        and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; 
    an attacker that can modify ciphertext in flight can get the receiver
        to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. 
    Verify each byte of the plaintext for ASCII compliance 
        (ie, look for high-ASCII values). 
            Noncompliant messages should raise an exception or return an 
                error that includes the decrypted plaintext 
                (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) 
    and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3
"""
from Crypto.Cipher import AES
import random


class CBC_IV_key:
    def __init__(self):
        self.key = random.randbytes(16)
        self.pt = b"nakamata@Stephanies-MacBook-Air-2 Cryptopals % g"

    def return_ct(self):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.key)
        return cipher.encrypt(self.pt)

    def is_valid(self, ciphertext: bytes):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.key)
        plaintext = cipher.decrypt(ciphertext)
        for byte in plaintext:
            if byte > 127:
                return b"This text is not valid: " + plaintext


boracle = CBC_IV_key()
ct = boracle.return_ct()
mod_ct = ct[:16] + bytes(16) + ct[:16]
error = boracle.is_valid(mod_ct)
if error:
    p1 = error[24:40]
    p3 = error[-16:]
    key = bytes(pt ^ dec for pt, dec in zip(p1, p3))
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    print("Decrypted plaintext is\n", cipher.decrypt(ct))
