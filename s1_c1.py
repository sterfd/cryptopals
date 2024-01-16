# Set 1 Challenge 1
# Convert hex to base64
# The string:

# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:

# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
# So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

# Cryptopals Rule
# Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.


"""
hex is base 16 where each digit is 4 bits
base 64 where each digit is 6 bits - == as padding at end

go through digits of hex string, use a mapping, and append to array of 2 bits
encode the binary data to base64 using a mapping

"""
hex_mapping = {
    "0": "0000",
    "1": "0001",
    "2": "0010",
    "3": "0011",
    "4": "0100",
    "5": "0101",
    "6": "0110",
    "7": "0111",
    "8": "1000",
    "9": "1001",
    "A": "1010",
    "B": "1011",
    "C": "1100",
    "D": "1101",
    "E": "1110",
    "F": "1111",
}

b64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def decode_hex(s):
    decoded_bits = []
    for ch in s.upper():
        decoded_bits.append(hex_mapping[ch])
    return "".join(decoded_bits)
    # go through digit in string
    # use a mapping
    # append to array
    # return array


def encode_bits(bit_string):
    encoded_b64 = []
    for digits in range(0, len(bit_string), 6):
        bin_index = int(bit_string[digits : digits + 6], base=2)
        encoded_b64.append(b64_map[bin_index])
    return "".join(encoded_b64)

    # go through chars in bit_string 6 at a time and encode to array


hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
bits = decode_hex(hex_string)
encoded = encode_bits(bits)
# print(bits)
print(encoded)


# using bytes
import base64

decoded_bytes = bytes.fromhex(hex_string)
encoded_64 = base64.b64encode(decoded_bytes)
# print(decoded_bytes)
# print(encoded_64)
