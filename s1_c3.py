# Set 1 Challenge 3
"""
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. 
Character frequency is a good metric. Evaluate each output and choose the one with the best score.
"""
# how to do scoring of character frequency?


def convert_stats(string):
    if string.isalpha():
        return string
    if string[-1].isnumeric():
        return
    return int(float(string[:4]) * 100) / 10000


def char_freq():
    copied_text = (
        "E	11.1607%	56.88	M	3.0129%	15.36"
        "A	8.4966%	43.31	H	3.0034%	15.31"
        "R	7.5809%	38.64	G	2.4705%	12.59"
        "I	7.5448%	38.45	B	2.0720%	10.56"
        "O	7.1635%	36.51	F	1.8121%	9.24"
        "T	6.9509%	35.43	Y	1.7779%	9.06"
        "N	6.6544%	33.92	W	1.2899%	6.57"
        "S	5.7351%	29.23	K	1.1016%	5.61"
        "L	5.4893%	27.98	V	1.0074%	5.13"
        "C	4.5388%	23.13	X	0.2902%	1.48"
        "U	3.6308%	18.51	Z	0.2722%	1.39"
        "D	3.3844%	17.25	J	0.1965%	1.00"
        "P	3.1671%	16.14	Q	0.1962%	1"
    )
    chr_freq = [
        convert_stats(entry) for entry in copied_text.split() if convert_stats(entry)
    ]
    char_freq_dict = {}
    for i in range(0, len(chr_freq), 2):
        char_freq_dict[chr_freq[i]] = chr_freq[i + 1]
    return char_freq_dict


char_percentages = char_freq()


# decryption


def xor_test(message):
    decoded_bytes = bytes.fromhex(message)
    for key in range(48, 123):
        xor1 = bytes(d1 ^ key for d1 in decoded_bytes)
        decrypted = bytes.hex(xor1)
        print(key, chr(key), xor1)
    # key = 88, char = X


encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_test(encrypted)


"""'
xor is one of the few operators that prseerve randomness in 1 adn 0 - 50% chance of 1 or 0 based on outcomes
with & or | - you end up with 3/4 ratio of 0 and 1
xor is invertable - you can undone the operation with key

"""
