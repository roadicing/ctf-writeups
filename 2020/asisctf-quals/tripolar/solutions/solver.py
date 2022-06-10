#!/usr/bin/env python3

import gmpy2
from Crypto.Util.number import *

def crow(x, y, z):
    return (x**3 + 3*(x + 2)*y**2 + y**3 + 3*(x + y + 1)*z**2 + z**3 + 6*x**2 + (3*x**2 + 12*x + 5)*y + (3*x**2 + 6*(x + 1)*y + 3*y**2 + 6*x + 2)*z + 11*x) // 6

def rev_crow(res, alpha):
    A = gmpy2.iroot(6 * res, 3)[0]
    B = gmpy2.iroot((6 * res - A**3)//3, 2)[0] + alpha
    z = A - B
    y = (-6 * res + A**3 + 3 * (B**2) + 2 * B - z - 6)//6
    x = B - y - 1
    return (x, y, z)

f = open('flag.enc', 'rb').read()
ct = bytes_to_long(f)

x, y, z = rev_crow(ct, 0)
assert crow(x, y, z) == ct

pk = gmpy2.gcd(x, y)
_enc = x // pk

p, q, r = rev_crow(pk, 1)
assert [i for i in map(isPrime, [p, q, r])] == [1] * 3 and crow(p, q, r) == pk

N = p * q * r
phi = (p - 1) * (q - 1) * (r - 1)

e = 31337
d = inverse(e, phi)

pt = pow(_enc, d, N)

FLAG = long_to_bytes(pt)
print(FLAG)

# ASIS{I7s__Fueter-PoLy4__c0nJ3c7UrE_iN_p4Ir1n9_FuNCT10n}