# Set 2 Challenge 15
# PKCS#7 padding validation
# Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

# The string:

# "ICE ICE BABY\x04\x04\x04\x04"
# ... has valid padding, and produces the result "ICE ICE BABY".

# The string:

# "ICE ICE BABY\x05\x05\x05\x05"
# ... does not have valid padding, nor does:

# "ICE ICE BABY\x01\x02\x03\x04"
# If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.


# Crypto nerds know where we're going with this. Bear with us.


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


padding_tests = [
    b"ICE ICE BABY\x04\x04\x04\x04",
    b"ICE ICE BABY\x05\x05\x05\x05",
    b"ICE ICE BABY\x01\x02\x03\x04",
    b'comment1"="cooking%20MCsuserdata"="what"=""=""=""=" the heck?admin"="true---"=""="comment2"="%20like%20a%20pound%20of%20bacon\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c',
]
# for test in padding_tests:
#     print(len(test))
#     print(validate_pkcs_padding(test, 16))
