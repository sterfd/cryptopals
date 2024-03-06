import base64
import random
from Crypto.Cipher import AES


# BASIC CONVERSIONS
def str_to_bytes(message: str, hex_str: str, b64_str: str) -> bytes:
    message_b = bytes(message, encoding="utf-8")
    decoded_hex = bytes.fromhex(hex_str)
    decoded_64 = base64.b64decode(b64_str)


# FREQUENCY SCORING

hp_freq = {
    " ": 0.1744,
    "e": 0.0983,
    "t": 0.0715,
    "a": 0.0655,
    "o": 0.0644,
    "h": 0.0555,
    "n": 0.0537,
    "r": 0.0533,
    "i": 0.0512,
    "s": 0.0485,
    "d": 0.0409,
    "l": 0.0359,
    "u": 0.024,
    "y": 0.0212,
    "g": 0.0212,
    "w": 0.0206,
    "m": 0.0182,
    "f": 0.0168,
    "c": 0.0165,
    "p": 0.0136,
    "b": 0.0131,
    "k": 0.0098,
    "v": 0.0071,
    "q": 0.001,
    "x": 0.0009,
    "j": 0.0009,
    "z": 0.0006,
}


def space_scoring(decoded):
    score = int(decoded.count(ord(" ")) / len(decoded) * 1000) / 1000
    return score  # higher score is better


def vowel_scoring(decoded):
    vowels = [ord(v) for v in ["a", "e", "i", "o", "u", " "]]
    score = 0
    for ch in bytes(decoded):
        if ch in vowels:
            score += 1
    return int(score / len(decoded) * 1000) / 1000  # higher score is better


def frequency_kl_scoring(decoded):
    """
    KL divergence, aka relative entropy:
    D_kl(p(x) || q(x)) = sum_for_all_x = p(x)ln(p(x)/q(x)) where p and q are probability distributions
    score of 0 means no entropy - same distribution
    """
    from collections import Counter
    import math

    for byte in decoded:
        if byte < 9 or 12 <= byte <= 31 or 91 <= byte <= 94 or byte > 122:
            return 100

    letter_count = Counter(str(decoded).lower())
    message_len = len(decoded)
    mess_freq = {
        ch: int(letter_count[ch] / message_len * 1000) / 1000 for ch in letter_count
    }
    KL_div_score = 0
    for ch in hp_freq:
        if ch in letter_count:
            KL_div_score += hp_freq[ch] * math.log(hp_freq[ch] / mess_freq[ch])
        else:
            KL_div_score += hp_freq[ch] * math.log(hp_freq[ch] / (10**-10))
    for ch in mess_freq:
        if not ch.isascii():
            KL_div_score += mess_freq
    return KL_div_score  # lower score is better


# ENCRYPTION
def fixed_xor(b1: bytes, b2: bytes) -> bytes:
    xor_bytes = bytes(d1 ^ d2 for d1, d2 in zip(b1, b2))
    return xor_bytes


def encrypt_repeating_xor(message: bytes, key: bytes) -> bytes:
    xor_array = []
    for idx, ch in enumerate(message):
        xor_array.append(ord(ch) ^ ord(key[idx % len(key)]))
    return b"".join(xor_array)


# DECRYPTING REPEATING XOR


def calc_hamming_distance(byte1, byte2) -> int:
    distance = sum((bin(b1 ^ b2).count("1") for b1, b2 in zip(byte1, byte2)))
    return distance


def calc_keysize(text_b: bytes) -> int:
    keysize_scores = []

    for keysize in range(2, 41):
        distances = []
        for i in range(0, len(text_b), keysize):
            first = text_b[i : keysize + i]
            second = text_b[keysize + i : keysize * 2 + i]
            distances.append(calc_hamming_distance(first, second) / keysize)
        avg_distance = sum(distances) / len(distances)
        keysize_scores.append((avg_distance, keysize))
    return sorted(keysize_scores)[0][1]


def make_transposed_keysize_blocks(text: bytes, keysize: int) -> list[bytes]:
    blocks = [[] for _ in range(keysize)]
    idx = 0
    for byte in text:
        blocks[idx % keysize].append(byte)
        idx += 1
    return blocks


def xor_key(entry: bytes, key: bytes) -> tuple[float, bytes]:
    decoded_bytes = bytes(a ^ key for a in entry)
    return (frequency_kl_scoring(decoded_bytes), decoded_bytes)


def break_repeating_xor(ciphertext: bytes, keysize: int) -> str:
    blocks = make_transposed_keysize_blocks(ciphertext, keysize)
    resulting_blocks = []

    for block in blocks:
        best_score, best_block = 100, None
        for i in range(0, 255):
            score, decoded_bytes = xor_key(block, i)
            if score < best_score:
                best_score = score
                best_block = decoded_bytes
        resulting_blocks.append(best_block)

    final_text = []
    for i in range(len(ciphertext)):
        final_text.append(chr(resulting_blocks[i % keysize][i // keysize]))

    return "".join(final_text)


# AES encryption


def text_to_blocks(text_b: bytes, blocksize: int) -> list[bytes]:
    blocks = [
        text_b[x * blocksize : (x * blocksize) + blocksize]
        for x in range(len(text_b) // blocksize)
    ]
    return blocks


def detect_ECB(ciphertext: bytes, blocksize: int) -> bool:
    blocks = text_to_blocks(ciphertext, blocksize)
    num_blocks = len(blocks)
    unique_blocks = len(set(blocks))
    if num_blocks != unique_blocks:
        return True
    return False


def pad_message(message: bytes, bs: int) -> bytes:
    padding_len = bs - (len(message) % bs)
    padding = padding_len * bytes([padding_len])
    message += padding
    return message


def decrypt_AES_ECB(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(message)
    for i in range(len(key) - 1, 1, -1):
        last_bytes = plaintext[-i:]
        if len(set(last_bytes)) == 1 and last_bytes[0] == len(last_bytes):
            return plaintext[:-i]
    return plaintext


def encrypt_AES_ECB(message: bytes, key: bytes) -> bytes:
    padded_message = pad_message(message, len(key))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded_message)


def encrypt_CBC(message: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = []
    bs = len(iv)
    padded = pad_message(message, bs)
    blocks = [padded[bs * i : (bs * (i + 1))] for i in range(len(padded) // bs + 1)]
    prev_block = iv
    for block in blocks:
        xor_block = bytes(b1 ^ b2 for b1, b2 in zip(prev_block, block))
        enc_block = cipher.encrypt(xor_block)
        ciphertext.append(enc_block)
        prev_block = enc_block
    return b"".join(ciphertext)


def decrypt_CBC(message: bytes, iv: bytes, key: bytes) -> bytes:
    plaintext = []
    bs = len(key)
    blocks = [message[bs * i : (bs * (i + 1))] for i in range(len(message) // bs)]
    prev = iv
    for block in blocks:
        dec_block = decrypt_AES_ECB(block, key)
        xored = bytes(b1 ^ b2 for b1, b2 in zip(dec_block, prev))
        plaintext.append(xored)
        prev = block
    return b"".join(plaintext)


def encryption_oracle_ECB_CBC(message, key_len):
    key = random.randbytes(key_len)
    pre_message = random.randbytes(random.randint(5, 10))
    post_message = random.randbytes(random.randint(5, 10))
    enc_mode = random.choice(["ecb", "cbc"])

    if enc_mode == "ecb":
        return encrypt_AES_ECB(pre_message + message + post_message, key)
    # cbc otherwise
    iv = random.randbytes(key_len)
    return encrypt_CBC(pre_message + message + post_message, key, iv)


def ECB_CBC_detection_oracle(ciphertext: bytes, key_size) -> None:
    if detect_ECB(ciphertext, key_size):
        print("ECB mode was detected by repeating blocks")
    else:
        print("Maybe CBC since ECB was not detected")


class PaddingError(Exception):
    pass


def validate_pkcs_padding(plaintext: bytes, blocksize: int) -> bytes:
    try:
        if len(plaintext) % blocksize != 0:
            raise PaddingError
        len_padding = plaintext[-1]
        if len(set([byte for byte in plaintext[-len_padding:]])) != 1:
            raise PaddingError
        return plaintext[:-len_padding]
    except PaddingError:
        # print("Invalid PKCS#7 padding error.")
        return


# CTR Mode
def decrypt_CTR(ct: bytes, nonce: int, key: bytes):
    pt = b""
    bs = len(key)
    for block in range(len(ct) // bs + 1):
        counter = nonce.to_bytes(length=bs // 2, byteorder="little") + block.to_bytes(
            length=bs // 2, byteorder="little"
        )
        keystream = encrypt_AES_ECB(counter, key)
        pt += bytes(k ^ c for k, c in zip(keystream, ct[block * bs : (block + 1) * bs]))
    return pt


def encrypt_CTR(pt: bytes, nonce: int, key: bytes):
    ct = b""
    bs = len(key)
    for block in range(len(pt) // bs + 1):
        counter = nonce.to_bytes(length=bs // 2, byteorder="little") + block.to_bytes(
            length=bs // 2, byteorder="little"
        )
        keystream = encrypt_AES_ECB(counter, key)
        ct += bytes(k ^ p for k, p in zip(keystream, pt[block * 16 : (block + 1) * 16]))
    return ct


# PRNGS
class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l, f = 18, 1812433253
    wmask = (1 << w) - 1
    lower_mask = (1 << r) - 1
    upper_mask = 1 << r

    def __init__(self, seed=5489):
        self.idx = self.n
        self.MT = [0] * self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = self.wmask & (
                self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i
            )

    def new_seed(self, seed):
        self.idx = self.n
        self.MT = [0] * self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = self.wmask & (
                self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i
            )

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (
                self.MT[(i + 1) % self.n] & self.lower_mask
            )
            xA = x >> 1
            xA = xA ^ self.a if (x % 2 != 0) else xA
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.idx = 0

    def extract_numbers(self):
        if self.idx >= self.n:
            self.twist()
        y = self.MT[self.idx]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.idx += 1
        return y & self.wmask
