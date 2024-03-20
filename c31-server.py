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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from c28 import SHA1
import random
import time
import threading


class Serv(BaseHTTPRequestHandler):
    hmac_key = None

    @classmethod
    def generate_hmac_key(cls):
        # Generate a random key for HMAC
        cls.hmac_key = random.randbytes(16)

    def insecure_compare(self, sig, computed_sig):
        for s, c in zip(sig, computed_sig):
            if s != c:
                return False
            time.sleep(0.05)
        return sig == computed_sig

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if "file" in query_params and "signature" in query_params:
            file_name = query_params["file"][0]
            signature = query_params["signature"][0]  # hexstring

            # Generate signature for the file
            computed_signature = self.hmac(file_name)  # hexstring

            # Use threading to perform the comparison asynchronously
            compare_thread = threading.Thread(
                target=self.compare_signatures,
                args=(signature, computed_signature),
            )
            compare_thread.start()
        else:
            print("Missing file or signature argument")
            self.send_response(400)

    def compare_signatures(self, signature, computed_signature):
        try:
            if self.insecure_compare(signature, computed_signature):
                self.send_response(200)
            else:
                self.send_response(500)
            self.end_headers()
        except ConnectionAbortedError:
            print("client connection was aborted")
        except Exception as e:
            print("error", e)
            self.send_response(500)

    def hmac(self, file_name):
        # get signature from file_name using sha1
        file = bytes(file_name, encoding="utf-8")
        if len(self.hmac_key) > 64:
            self.hmac_key = SHA1(self.hmac_key)
        else:
            self.hmac_key = self.hmac_key + bytes(64 - len(self.hmac_key))
        o_pad, i_pad = bytes([0x5C]) * 64, bytes([0x36]) * 64
        o_key = bytes([k ^ o for k, o in zip(self.hmac_key, o_pad)])
        i_key = bytes([k ^ i for k, i in zip(self.hmac_key, i_pad)])
        print("uhh inner sha1", (hex(SHA1(i_key + file))))
        inner = bytes.fromhex(hex(SHA1(i_key + file))[2:])
        return hex(SHA1(o_key + inner))[2:]


# Generate HMAC key before starting the server
Serv.generate_hmac_key()

httpd = HTTPServer(("localhost", 8080), Serv)
httpd.serve_forever()
