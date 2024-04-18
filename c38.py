# Set 5 Challenge 38
# Offline dictionary attack on simplified SRP

"""
S
    x = SHA256(salt|password)
        v = g**x % n

C->S
    I, A = g**a % n

S->C
    salt, B = g**b % n, u = 128 bit random number

C
    x = SHA256(salt|password)
        S = B**(a + ux) % n
        K = SHA256(S)

S
    S = (A * v ** u)**b % n
        K = SHA256(S)
    
C->S Send HMAC-SHA256(K, salt)

S->C Send "OK" if HMAC-SHA256(K, salt) validates


Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).

"""


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
        self.a = random.randint(1, 2**128)  # private key

    def send_email_pkA(self):
        self.pkA = modexp(b=self.g, e=self.a, m=self.N)
        print(f"Client sent to server email and A")
        return self.I, self.pkA

    def receive_salt_pkB(self, salt, pkB, u):
        # print(f"Client has received salt, public key B, and u from server")
        self.pkB = pkB
        self.salt = salt
        self.u = u

        saltpassword = str(self.salt) + str(self.P)
        x = int(hashlib.sha256(saltpassword.encode("utf-8")).hexdigest(), base=16)
        base = self.pkB - self.k * modexp(b=self.g, e=x, m=self.N)
        exponent = self.a + self.u * x
        S = str(modexp(b=base, e=exponent, m=self.N))
        self.K = hashlib.sha256(S.encode("utf-8")).digest()
        # print(f"Client has computed session key")
        # print(f"Client sending to server HMAC-SHA256 of K and salt")
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

    def agree_NgkIP(self):
        return self.N, self.g, self.k, self.user["email"], self.user["password"]

    def generate_salt(self):
        self.b = 0
        self.user["salt"] = 0
        saltpassword = str(self.user["salt"]) + self.user["password"]
        x = int(
            hashlib.sha256(saltpassword.encode("utf-8")).hexdigest(), base=16
        )  # private key
        self.user["v"] = modexp(b=self.g, e=x, m=self.N)  # password verifier
        # print(f"{saltpassword =}, {x = }, {self.user['v'] =}")
        print(f"Server has generated salt, private key x, and password verifier v")

    def receive_email_pkA(self, I, A):
        self.user["A"] = A
        print(f"Server received email and public key A from client")

    def send_salt_pkB(self):
        B = self.k * self.user["v"] + modexp(b=self.g, e=self.b, m=self.N)
        # print(
        #     f"{self.k = }, {self.user['v'] = }, {modexp(b=self.g, e=self.b, m=self.N) = }, {B = }"
        # )
        self.user["u"] = 0
        # print(
        #     f"Server sending to client salt {self.user['salt'] = }, public key {B = }, random {self.user['u'] = }"
        # )
        return self.user["salt"], B, self.user["u"]

    def validate_hmac(self, hmac):
        Avu = self.user["A"] * modexp(b=self.user["v"], e=self.user["u"], m=self.N)
        S = str(modexp(b=Avu, e=self.b, m=self.N))
        self.user["K"] = hashlib.sha256(S.encode("utf-8")).digest()
        # print(f"Server has computed session key ")

        server_hmac = HMAC_SHA256(
            self.user["K"], str(self.user["salt"]).encode("utf-8")
        )
        # print(f"Validating HMAC from client... {server_hmac == hmac}\n")
        return server_hmac == hmac


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


def MITM():
    def generate_pkB():
        N = int(
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
        all_pkb = []
        with open("pw200.txt", "r") as f:
            pws = f.readlines()
            for pw in pws:
                secret_key = int(
                    hashlib.sha256(b"0" + pw.strip().encode("utf-8")).hexdigest(),
                    base=16,
                )
                # print(secret_key)
                all_pkb.append(3 * modexp(2, secret_key, N) + 1)
        return all_pkb

    user = "username"
    with open("pw200.txt", "r") as f:
        pws = f.readlines()
        pw = random.choice(pws).strip()
    Steve = Server(user, pw)
    Carol = Client()
    Carol.receive_NgkIP(*Steve.agree_NgkIP())  # share g, k, email, pw, N
    Steve.generate_salt()  # salt, x, v

    intercept_I, intercept_A = Carol.send_email_pkA()
    Steve.receive_email_pkA(intercept_I, intercept_A)
    Steve.send_salt_pkB()
    pkB_list = generate_pkB()
    # print(pkB_list)
    for idx, pkB in enumerate(pkB_list):
        hmac = Carol.receive_salt_pkB(0, pkB, 0)
        if Steve.validate_hmac(hmac):
            print("FOUND THE PASSWORD")
            with open("pw200.txt", "r") as f:
                pws = f.readlines()
                print("password =", pws[idx])


MITM()
