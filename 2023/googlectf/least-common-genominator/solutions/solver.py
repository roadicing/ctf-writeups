#!/usr/bin/env python3

from math import gcd
from gmpy2 import invert
from functools import reduce
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime, long_to_bytes

class LCG:
    def __init__(self, seed, p, m, c):
        self.state = seed
    def next(self):
        self.state = (self.state * m + c) % p
        return self.state

def recover_p(s):
    diffs = [s2 - s1 for s1, s2 in zip(s, s[1:])]
    zeroes = [t3 * t1 - t2 * t2 for t1, t2, t3 in zip(diffs, diffs[1:], diffs[2:])]
    p = abs(reduce(gcd, zeroes))
    return p

def recover_m(s, p):
    m = (s[2] - s[1]) * invert(s[1] - s[0], p) % p
    return m

def recover_c(s, p, m):
    c = (s[1] - s[0] * m) % p
    return c

outputs = list(map(int, open("dump.txt", "r").read().split('\n')[:-1]))
p = recover_p(outputs)
m = recover_m(outputs, p)
c = recover_c(outputs, p, m)

seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
lcg = LCG(seed, p, m, c)

primes_arr = []
primes_n = 1
while True:
    for i in range(8):
        while True:
            prime_candidate = lcg.next()
            if not isPrime(prime_candidate):
                continue
            elif prime_candidate.bit_length() != 512:
                continue
            else:
                primes_n *= prime_candidate
                primes_arr.append(int(prime_candidate))
                break
    if primes_n.bit_length() > 4096:
        print("bit length", primes_n.bit_length())
        primes_arr.clear()
        primes_n = 1
        continue
    else:
        break

f = open("public.pem", "r").read()
rsa = RSA.import_key(f)

n, e = rsa.n, rsa.e
assert all([n % i == 0 for i in primes_arr])

phi = 1
for k in primes_arr:
    phi *= (k - 1)

d = pow(e, -1, phi)

ct = int.from_bytes(open("flag.txt", "rb").read(), "little")
pt = pow(ct, d, n)

FLAG = long_to_bytes(pt)
print(FLAG) # CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}