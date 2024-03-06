# Set 1 Challenge 2
# Fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.

# If your function works properly, then when you feed it the string:

# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:

# 686974207468652062756c6c277320657965
# ... should produce:

# 746865206b696420646f6e277420706c6179


def xor_strings(str1, str2):
    decode1 = bytes.fromhex(str1)
    decode2 = bytes.fromhex(str2)
    xor_bytes = bytes(d1 ^ d2 for d1, d2 in zip(decode1, decode2))
    xor_encoded = bytes.hex(xor_bytes)
    return xor_encoded


string1 = "1c0111001f010100061a024b53535009181c"
string2 = "686974207468652062756c6c277320657965"
xor_result = xor_strings(string1, string2)
print(xor_result)
