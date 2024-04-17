# Set 5 Challenge 36
# Implement Secure Remote Password (SRP)
"""

To understand SRP, look at how you generate an AES key from DH; now, 
    just observe you can do the "opposite" operation an generate a numeric parameter from a hash. Then:

Replace A and B with C and S (client & server)

*C & S*
    Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

*S*
    Generate salt as random integer
    Generate string xH=SHA256(salt|password)
    Convert xH to integer x somehow (put 0x on hexdigest)
    Generate v=g**x % N
    Save everything but x, xH

*C->S*
    Send I, A=g**a % N (a la Diffie Hellman)

*S->C*
    Send salt, B=kv + g**b % N

*S, C*
    Compute string uH = SHA256(A|B), u = integer of uH

*C*
    Generate string xH=SHA256(salt|password)
    Convert xH to integer x somehow (put 0x on hexdigest)
    Generate S = (B - k * g**x)**(a + u * x) % N
    Generate K = SHA256(S)

*S*
    Generate S = (A * v**u) ** b % N
    Generate K = SHA256(S)
C->S
    Send HMAC-SHA256(K, salt)
S->C
    Send "OK" if HMAC-SHA256(K, salt) validates
You're going to want to do this at a REPL of some sort; it may take a couple tries.

It doesn't matter how you go from integer to string or string to integer 
    (where things are going in or out of SHA256) as long as you do it consistently. 
    I tested by using the ASCII decimal representation of integers as input to SHA256, 
        and by converting the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password into the public keys. 
    The server also takes an extra step to avoid storing an easily crackable password-equivalent."""

import random
import hashlib
from c33 import modexp


class Client:
    def __init__(self):
        pass

    def receive_NgkIP(self, N, g, k, email, password):
        self.N = N
        self.g = g
        self.k = k
        self.I = email
        self.P = password
        print(
            f"Client and server have agreed on values {g =}, {k=}, {email=}, {password=}, and N=Nist prime"
        )
        self.a = random.randint(1, N - 1)  # private key

    def send_email_pkA(self):
        public_key = modexp(b=self.g, e=self.a, m=self.N)
        self.pkA = public_key
        print(f"Client sent to server email and public key A")
        return self.I, public_key

    def receive_salt_pkB(self, salt, pkB):
        print(f"Client has received salt and public key B from server")
        self.pkB = pkB
        self.salt = salt
        AB = str(self.pkA) + str(self.pkB)
        self.u = int(hashlib.sha256(AB.encode("utf-8")).hexdigest(), base=16)
        print(f"Client has calculated random scrambling parameter")

    def compute_session_key(self):
        saltpassword = str(self.salt) + str(self.P)
        x = int(hashlib.sha256(saltpassword.encode("utf-8")).hexdigest(), base=16)
        base = self.pkB - self.k * modexp(b=self.g, e=x, m=self.N)
        exponent = self.a + self.u * x
        S = str(modexp(b=base, e=exponent, m=self.N))
        self.K = hashlib.sha256(S.encode("utf-8")).digest()
        print(f"Client has computed session key")
        print(f"Client sending to server HMAC-SHA256 of K and salt")
        return HMAC_SHA256(self.K, str(self.salt).encode("utf-8"))


class Server:
    def __init__(self, email, password):
        self.N = int(
            (
                """0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff"""
            ).replace("\n", ""),
            base=16,
        )
        self.g = 2
        self.k = 3
        self.user = {"email": email, "password": password}
        self.b = random.randint(1, self.N - 1)

    def agree_NgkIP(self):
        return self.N, self.g, self.k, self.user["email"], self.user["password"]

    def generate_salt(self):
        self.user["salt"] = random.randint(100000, 1000000)
        saltpassword = str(self.user["salt"]) + self.user["password"]
        x = int(
            hashlib.sha256(saltpassword.encode("utf-8")).hexdigest(), base=16
        )  # private key
        self.user["v"] = modexp(b=self.g, e=x, m=self.N)  # password verifier
        print(
            f"Server has generated salt, private key x, and password verifier v. Stored salt and v in user db"
        )

    def receive_email_pkA(self, I, A):
        self.user["A"] = A
        print(f"Server received email and public key A from client")

    def send_salt_pkB(self):
        B = self.k * self.user["v"] + modexp(b=self.g, e=self.b, m=self.N)
        print(f"Server sending to client salt and public key B")
        AB = str(self.user["A"]) + str(B)
        self.user["u"] = int(hashlib.sha256(AB.encode("utf-8")).hexdigest(), base=16)
        print(f"Server has calculated random scrambling parameter")
        return self.user["salt"], B

    def validate_hmac(self, hmac):
        Avu = self.user["A"] * modexp(b=self.user["v"], e=self.user["u"], m=self.N)
        S = str(modexp(b=Avu, e=self.b, m=self.N))
        self.user["K"] = hashlib.sha256(S.encode("utf-8")).digest()
        print(f"Server has computed session key K")

        server_hmac = HMAC_SHA256(
            self.user["K"], str(self.user["salt"]).encode("utf-8")
        )
        print(f"Validating HMAC from client...\n{server_hmac == hmac}\n")


def HMAC_SHA256(K: bytes, m: bytes):
    bs = 64
    K = hashlib.sha256(K).digest() if len(K) > bs else K
    K_prime = K + bytes((bs - len(K)))
    K_opad = bytes(
        [k_bytes ^ pad for k_bytes, pad in zip(K_prime, (bs * bytes.fromhex("5c")))]
    )
    K_ipad = bytes(
        [k_bytes ^ pad for k_bytes, pad in zip(K_prime, (bs * bytes.fromhex("36")))]
    )
    return hashlib.sha256(K_opad + hashlib.sha256(K_ipad + m).digest()).digest()


Steve = Server("hehe@gmail.com", "password123")
Carol = Client()
Carol.receive_NgkIP(*Steve.agree_NgkIP())
Steve.generate_salt()
Steve.receive_email_pkA(*Carol.send_email_pkA())
Carol.receive_salt_pkB(*Steve.send_salt_pkB())
Steve.validate_hmac(Carol.compute_session_key())
