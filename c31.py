# Set 4 Challenge 31
# Implement and break HMAC-SHA1 with an artificial timing leak

"""
The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever), 
    write a tiny application that has a URL that takes a "file" argument and a "signature" argument, 
    like so:

http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", 
    using the "==" operator to compare the valid MAC for a file with the "signature" parameter 
    (in other words, verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", 
    that implements the == operation by doing byte-at-a-time comparisons with early exit 
    (ie, return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming requests, 
    and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the valid MAC for any file.

Why artificial delays?
Early-exit string compares are probably the most common source of cryptographic timing leaks, 
    but they aren't especially easy to exploit. In fact, many timing leaks 
    (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. 
    To play with attacking real-world timing leaks, you have to start writing low-level timing code. 
We're keeping things cryptographic in these challenges.
"""

import requests
import time


def break_HMAC():
    def argmin(x):
        return min(range(len(x)), key=lambda i: x[i])

    hex_ch = "0123456789abcdef"
    sig = ["0"] * 40
    url = "http://localhost:8080"

    for idx in range(40):
        print(f'at idx {idx} sig is currently {"".join(sig)}')
        time_diffs = []
        prev_t = time.time()
        for ch in hex_ch:
            sig[idx] = ch
            resp = requests.get(
                url, params={"file": "foo", "signature": "".join(sig)}, timeout=30
            )
            current_t = time.time()
            time_diffs.append(current_t - prev_t)
            prev_t = current_t
            print(time_diffs)
        smallest_t = argmin(time_diffs)
        sig[idx] = hex_ch[smallest_t]
    return sig


best_sig = break_HMAC()
# repsonse = requests.get()
