#!/usr/bin/env sage

# http://www.monnerat.info/publications/anomalous.pdf

import re
from pwn import *

IP = b"notbefoooled.challenges.ooo"
PORT = 5000

'''
BITS = 113

def gen_anomalous_curve(BITS):
    for y in range(2^BITS, 2^(BITS + 1)):
        res = 1 + 3 * y^2
        if res % 4 != 0:
            continue
        p = res // 4
        if not is_prime(p):
            continue
        for b in range(1, p):
            try:
                E = EllipticCurve(GF(p), [0, b])
                if p == E.order():
                    return (0, b, p)
            except:
                continue
    return [None] * 3

a, b, p = gen_anomalous_curve(BITS)
print((a, b, p))

# (0, 13, 80879840001451919384001045261060060287704603603838136804984905273467)
'''

a, b, p = (0, 13, 80879840001451919384001045261060060287704603603838136804984905273467)
E = EllipticCurve(GF(p), [a, b])

io = remote(IP, PORT)

io.sendlineafter(b"a = ", str(a).encode())
io.sendlineafter(b"b = ", str(b).encode())
io.sendlineafter(b"p = ", str(p).encode())

G = E(list(map(int, re.findall(b"\d+", io.recvline()))))

k = randrange(1, p)
P = k * G

io.sendlineafter(b"x = ", str(P[0]).encode())
io.sendlineafter(b"y = ", str(P[1]).encode())

io.interactive()

# OOO{be_Smarter_like_you_just_did}