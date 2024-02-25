# Set 3 Challenge 22
# Crack an MT19937 seed
# Make sure your MT19937 accepts an integer seed value.
#   Test it (verify that you're getting the same sequence of outputs given a seed).

# Write a routine that performs the following operation:

# Wait a random number of seconds between, I don't know, 40 and 1000.
# Seeds the RNG with the current Unix timestamp
# Waits a random number of seconds again.
# Returns the first 32 bit output of the RNG.
# You get the idea. Go get coffee while it runs.
#    Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

# From the 32 bit RNG output, discover the seed.

import time
import random
from c21 import MT19937


def set_challenge_seed():
    start = int(time.time())
    print("Start time,", start)
    start_delay, return_delay = random.randint(40, 1000), random.randint(40, 1000)

    time_seed = start + start_delay * 60
    rng = MT19937(time_seed)
    num = rng.extract_numbers()

    end = time_seed + return_delay * 60
    print("End time", end)
    print("Random number", num)
    return start, end, num, time_seed


def find_seed(start, end, target_num):
    print("Finding the seed... ")
    for test_seed in range(start + 40 * 60, end - 40 * 60):
        generator = MT19937(test_seed)
        if generator.extract_numbers() == target_num:
            return test_seed


start, end, num, secret = set_challenge_seed()
time_seed = find_seed(start, end, num)
if secret == time_seed:
    print("Found seed", time_seed)
