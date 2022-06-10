#!/usr/bin/env python3

from pwn import *
import re

IP = b"168.119.108.148"
PORT = 13010

# https://math.stackexchange.com/questions/144194/how-to-find-the-order-of-elliptic-curve-over-finite-field-extension
def extension_degree(p, order, n):
    t = p + 1 - order
    s = [2, t]
    for i in range(n - 1):
        s.append(t * s[-1] - p * s[-2])
    return p**n + 1 - s[-1]

io = remote(IP, PORT)

while True:
    _ = io.recvuntil(b"p = ")
    p = int(io.recvline().strip())
    _ = io.recvuntil(b"k = ")
    k = int(io.recvline().strip())
    _ = io.recvuntil(b"n = ")
    n = int(io.recvline().strip()[:-1])
    ans = extension_degree(p, k, n)
    io.sendline(str(ans))
    res = io.recvline()
    if b"good job" in res:
        continue
    elif b"not true" in res:
        break
    else:
        break

print(res)

# ASIS{wH47_iZ_mY_5P1R!TuAL_4NiMal!???}