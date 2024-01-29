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
    "h": 0.0555,
    "a": 0.0655,
    "r": 0.0533,
    "y": 0.0212,
    " ": 0.1744,
    "p": 0.0136,
    "o": 0.0644,
    "t": 0.0715,
    "e": 0.0983,
    "n": 0.0537,
    "d": 0.0409,
    "s": 0.0485,
    "c": 0.0165,
    "b": 0.0131,
    "w": 0.0206,
    "l": 0.0359,
    "i": 0.0512,
    "v": 0.0071,
    "m": 0.0182,
    "u": 0.024,
    "f": 0.0168,
    "k": 0.0098,
    "x": 0.0009,
    "g": 0.0212,
    "j": 0.0009,
    "z": 0.0006,
    "q": 0.001,
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
    return KL_div_score  # lower score is better


# ENCRYPTION
def fixed_xor(b1: bytes, b2: bytes) -> bytes:
    xor_bytes = bytes(d1 ^ d2 for d1, d2 in zip(b1, b1))
    return bytes.hex(xor_bytes)


def encrypt_repeating_xor(message: bytes, key: bytes) -> bytes:
    xor_array = []
    for idx, ch in enumerate(message):
        xor_array.append(ord(ch) ^ ord(key[idx % len(key)]))
    return bytes.hex(bytes(xor_array))


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
    return (vowel_scoring(decoded_bytes), decoded_bytes)


def break_repeating_xor(ciphertext: bytes, keysize: int) -> str:
    blocks = make_transposed_keysize_blocks(ciphertext, keysize)
    resulting_blocks = []

    for block in blocks:
        best_score, best_block = 0, None
        for i in range(0, 255):
            score, decoded_bytes = xor_key(block, i)
            if score > best_score:
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
    padding = b"\x04"
    padding_len = 0 if len(message) % bs == 0 else bs - (len(message) % bs)
    message += padding * padding_len
    return message


def decrypt_AES_ECB(message: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(message)


def encrypt_AES_ECB(message: bytes, key: bytes) -> bytes:
    padded_message = pad_message(message, len(key))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded_message)


def encrypt_CBC(message: bytes, iv: bytes, key: bytes) -> bytes:
    ciphertext = []
    bs = len(iv)
    blocks = [message[bs * i : (bs * (i + 1))] for i in range(len(message) // bs)]
    blocks[-1] = pad_message(blocks[-1], bs)
    prev_block = iv
    for block in blocks:
        xor_block = bytes(b1 ^ b2 for b1, b2 in zip(prev_block, block))
        enc_block = encrypt_AES_ECB(xor_block, key)
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
