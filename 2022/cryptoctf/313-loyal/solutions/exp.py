#!/usr/bin/env python3

import re
from pwn import *
from Crypto.Util.number import getPrime

IP = "07.cr.yp.toc.tf"
PORT = 31377

n = getPrime(512)
g = n + 1
poly = [1]

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", "s")
io.sendlineafter("poly \n", f"{n}, {g}, {poly}")

result_list = []
while True:
    result = io.recvline()
    if b"result" not in result:
        break
    result_list += [int(re.findall(b"\d+", result)[1])]

FLAG = bytes([j % 2**10 for j in sorted([(n - (pow(i, n - 1, n**2) // n)) for i in result_list])])
print(FLAG)

# CCTF{4n0t3R_h0MomORpH1C_3NcRyP7!0n_5CH3Me!}