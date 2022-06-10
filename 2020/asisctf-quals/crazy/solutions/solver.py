#!/usr/bin/env python3

import re
import gmpy2
from Crypto.Util.number import *

# Based on https://en.wikipedia.org/wiki/Blum–Goldwasser_cryptosystem#Decryption
# The modified version involves an unknown xorkey, but since only the lower `h = 10` bits are involved during the bitwise AND (&) operation, we can simply brute force it.
def decrypt(ct, pk, sk):
    c, s = ct
    N = pk
    p, q = sk
    h = len(bin(len(bin(N)[2:]))[2:]) - 1
    if len(bin(c)[2:]) % h != 0:
        c = '0' * (h - len(bin(c)[2:]) % h) + bin(c)[2:]
    else:
        c = bin(c)[2:]
    t = len(c) // h
    d_p = (((p + 1) // 4)**(t + 1)) % (p - 1)
    d_q = (((q + 1) // 4)**(t + 1)) % (q - 1)
    u_p = pow(s, d_p, p)
    u_q = pow(s, d_q, q)
    _, r_p, r_q = gmpy2.gcdext(p, q)
    C = [c[h * i: h * i + h] for i in range(t)]
    pt_list = []
    for xorkey in range(2**h):
        s_0 = (u_q * r_p * p + u_p * r_q * q) % N
        M = []
        for i in range(t):
            s_i = pow(s_0, 2, N)
            k = bin(s_i)[2:][-h:]
            m = bin(int(C[i], 2) ^ int(k, 2) & xorkey)[2:].zfill(h)
            M.append(m)
            s_0 = s_i
        pt = long_to_bytes(int(''.join(M), 2))
        pt_list.append(pt)
    return pt_list

f = open("output.txt", 'rb').read().split(b'\n')[:-1]

pk_list = []
enc_list = []
for data in f:
    res = list(map(int, re.findall(b"\d+", data)))
    pk_list.append(int(res[0]))
    enc_list.append((res[1], res[2]))

known = 0
for i in pk_list:
    if known == 1:
        break
    for j in pk_list:
        if gmpy2.gcd(i, j) != 1 and i != j:
            p = gmpy2.gcd(i, j)
            q = i // p
            N = p * q
            known = 1
            break

ct = enc_list[pk_list.index(N)]

pt_list = decrypt(ct, N, (p, q))
for pt in pt_list:
    if b"ASIS{" in pt:
        print(pt)

# ASIS{1N_h0nOr_oF__Lenore__C4r0l_Blum}