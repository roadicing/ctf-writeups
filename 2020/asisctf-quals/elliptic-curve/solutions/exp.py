#!/usr/bin/env sage

import hashlib
import string
import random
from Crypto.Util.number import *
from pwn import *

IP = b"76.74.178.201"
PORT = 9531

dic = string.ascii_letters + string.digits

def bypass_POW(io):
    res = io.recv().strip().split(b"(X)[-6:] = ")
    hash_type = res[0].split(b"that ")[1].decode()
    suffix = res[1][:6].decode()
    length = int(res[1][-2:])
    while True:
        ans = ''.join(random.choices(dic, k = length))
        h = getattr(hashlib, hash_type)(ans.encode()).hexdigest()
        if h.endswith(suffix):
            return ans

while True:
    try:
        io = remote(IP, PORT)
        ans = bypass_POW(io)
        io.sendline(ans)
        _ = io.recvuntil("P = ")
        P = eval(io.recvline().strip())
        k = int(re.findall(b"\d+", io.recvline())[0])
        a = -1
        p = P[0] + 1
        b = (P[1]^2 - P[0]^3 - a * P[0]) % p
        E = EllipticCurve(GF(p), [a, b])
        Q = E(P) * k
        io.sendline(str((Q[0], Q[1])))
        sleep(1)
        print(io.recv())
        break
    except:
        continue

# ASIS{4n_Ellip71c_curve_iZ_A_pl4Ne_al9ebr4iC_cUrv3}