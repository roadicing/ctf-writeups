#!/usr/bin/env python3
from random import randrange
from gmpy2 import *
from fast import random_prime

p, q = random_prime(), random_prime()
assert is_prime(p) and is_prime(q)
assert gcd(65537, (p - 1) * (q - 1)) == 1

n = p * q

m = open('flag.txt', 'rb').read().strip()
assert len(m) <= 100
m = int.from_bytes(m, 'big')
m |= randrange(0, n, 1 << 800)

print('n = {:#x}'.format(n))
print('c = {:#x}'.format(pow(m, 65537, n)))

