#!/usr/bin/env sage

import re
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

IP = b"coooppersmith.challenges.ooo"
PORT = 5000

io = remote(IP, PORT)

user_input = b"000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111"

io.sendline(user_input)
_ = io.recvline()
pubkey = RSA.import_key(io.recvuntil(b"-----END RSA PUBLIC KEY-----\n"))
N = pubkey.n
e = pubkey.e

_ = io.recvline()
numsum_ct = int(io.recvline().strip(), 16)

for x in range(0, 2**16):
    r = int(user_input, 16) * 2**32 + x
    if (N - 1) % r == 0:
        break

P.<x> = PolynomialRing(Zmod(N))
f = x + inverse_mod(2 * r, N)
k_0 = int(f.small_roots(X = r, beta = 0.4)[0])

p = 2 * r * k_0 + 1
q = N // p

assert(N == p * q)

d = inverse_mod(e, (p - 1) * (q - 1))
numsum_pt = pow(numsum_ct, d, N)

numsum = sum(list(map(int, re.findall(b"\d+", long_to_bytes(numsum_pt))[-2:])))

io.sendline(str(numsum).encode())
_ = io.recvline()
ct = int(io.recvline().strip(), 16)
pt = pow(ct, d, N)

FLAG = long_to_bytes(pt)
print(FLAG)

# OOO{Be_A_Flexible_Coppersmith}