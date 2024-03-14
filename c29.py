# Set 4, Challenege 29
# Break a SHA-1 keyed MAC using length extension

"""
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the output of SHA-1 and use it as a new starting point for SHA-1, 
    thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, 
    any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; 
    your forged message will need to include that padding. We call this "glue padding". 
    The final message you actually forge will be:

    SHA1(key || original-message || glue-padding || new-message)

(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, 
    you'll need to know the original bit length of the message; the message itself is known to the attacker, 
    but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message 
    and verify that you're generating the same padding that your SHA-1 implementation is using. 
    This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge 
    --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c 
    (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key 
    (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".

***This is a very useful attack.***
For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
"""

from c28 import SHA1
import random


def SHA1_states(
    message: bytes,
    states,
    len_added,
) -> int:
    def lrotate(bits, amount):
        return ((bits << amount) | (bits >> (32 - amount))) & 0xFFFFFFFF

    def fk(i, b, c, d):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40 or i >= 60:
            f = b ^ c ^ d
            k = 0x6ED9EBA1 if i < 40 else 0xCA62C1D6
        else:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        return f, k

    h0, h1, h2, h3, h4 = states
    mask = 0xFFFFFFFF

    # preprocess
    add_zeros = (119 - (len_added % 64)) % 64
    message += (
        bytes([128]) + bytes(add_zeros) + (len_added * 8).to_bytes(8, byteorder="big")
    )

    # split into 64 byte chunks
    for chunk_idx in range(len(message) // 64):
        chunk = message[chunk_idx * 64 : (chunk_idx + 1) * 64]
        word_bytes = [chunk[i * 4 : (i + 1) * 4] for i in range(16)]
        words = [int.from_bytes(x, byteorder="big") for x in word_bytes]

        for i in range(16, 80):  # expand each block of 16 bytes to 80
            w_i = words[i - 3] ^ words[i - 8] ^ words[i - 16] ^ words[i - 14]
            words.append(lrotate(w_i, 1))

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            f, k = fk(i, b, c, d)
            temp = lrotate(a, 5) + f + e + k + words[i] & mask
            e, d = d, c
            c = lrotate(b, 30)
            b, a = a, temp

        h0 = (h0 + a) & mask
        h1 = (h1 + b) & mask
        h2 = (h2 + c) & mask
        h3 = (h3 + d) & mask
        h4 = (h4 + e) & mask

    return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4


def MD_padding(msg):
    add_zeros = (119 - (len(msg) % 64)) % 64
    return bytes([128]) + bytes(add_zeros) + (len(msg) * 8).to_bytes(8, byteorder="big")


msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
secret_prefix = random.randbytes(random.randint(16, 60))
hashed_msg = SHA1(secret_prefix + msg)
hex_hash = hex(hashed_msg)[2:]
if len(hex_hash) % 2 == 1:
    hex_hash = "0" + hex_hash
MAC = bytes.fromhex(hex_hash)


def forge_mac(new_msg):
    h = [MAC[i * 4 : (i + 1) * 4] for i in range(len(MAC) // 4)]
    h = [int.from_bytes(i, byteorder="big") for i in h]

    for guess in range(16, 61):
        glue_padding = MD_padding(bytes(guess) + msg)
        len_added = guess + len(msg) + len(glue_padding) + len(new_msg)

        forged_msg = SHA1_states(new_msg, h, len_added)
        final_msg = SHA1(secret_prefix + msg + glue_padding + new_msg)

        if forged_msg == final_msg:
            print("len of secret prefix", guess)
            print(hex(forged_msg))
            return True


new_msg = b";admin=true"
print(forge_mac(new_msg))
