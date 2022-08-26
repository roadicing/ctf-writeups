#!/usr/bin/env python3

import re
from pwn import *
from Crypto.Util.number import *

IP = "04.cr.yp.toc.tf"
PORT = 37713

NBITS = 1024

def construct_p(n):
    for i in range(0, NBITS):
        for j in range(i + 1, NBITS):
            ar = [i, j]
            _B = [int(b) for b in bin(n)[2:]]
            for i in range(len(ar)): _B[ar[i]] = (_B[ar[i]] + 1) % 2
            N = int(''.join([str(b) for b in _B]), 2)
            if isPrime(N):
                return (i, j, N)

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", "g")
e, N = [int(re.findall(b"\d+", io.recvline())[0]) for _ in range(2)]

x, y, p = construct_p(N)

io.sendlineafter("[Q]uit\n", 'a')
io.sendlineafter("like: 14, 313\n", f"{x}, {y}")

MSG = "4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :P"
m = bytes_to_long(MSG.encode('utf-8'))

d = inverse(e, p - 1)
sig = pow(m, d, p)

io.sendlineafter("[Q]uit\n", 'v')
io.sendlineafter("verify: ", str(sig))

io.interactive()

# CCTF{R3aLlY_tH1S_1z_Seiferts_R54_AT7aCk!!?}