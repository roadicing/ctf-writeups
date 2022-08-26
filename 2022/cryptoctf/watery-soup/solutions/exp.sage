#!/usr/bin/env sage

import itertools
from pwn import *
from Crypto.Util.number import long_to_bytes

IP = "05.cr.yp.toc.tf"
PORT = 37377

io = remote(IP, PORT)

moduli = []
residues_list = [[] for _ in range(4)]
for idx in range(4):
    while True:
        try:
            p = random_prime(2^128, lbound = 2^127)
            g = ZZ(Mod(1, p).nth_root(3))
            r = inverse_mod(g - 1, p)
            assert 64 < r.nbits() < 128
            assert 64 < ((r * g) % p).nbits() < 128
            break
        except:
            continue

    moduli += [p]

    res_list = []
    for i in [r, (r * g) % p]:
        io.sendlineafter("[Q]uit\n", "s")
        io.sendlineafter("here: \n", str(p))
        io.sendlineafter("here: \n", str(i))
        res_list += [ZZ(re.findall(b"\d+", io.recvline())[0])]

    P.<x> = PolynomialRing(GF(p))
    f = (r^3 * x^3 + r^4 * x * g - x^2 - r) - (r^3 * x * res_list[1] - res_list[0])

    residues_list[idx] = [ZZ(i) for i, _ in f.roots()]

for residues in list(itertools.product(*residues_list)):
    FLAG = long_to_bytes(crt(list(residues), moduli))
    if b"CCTF{" in FLAG:
        print(FLAG)

# CCTF{Pl34se_S!r_i_w4N7_5omE_M0R3_5OuP!!}