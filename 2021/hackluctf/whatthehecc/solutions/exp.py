#!/usr/bin/env sage

import re
from pwn import *
from Crypto.Hash import SHA3_256

IP = b"flu.xxx"
PORT = 20085

def hash(msg):
    h_obj = SHA3_256.new()
    h_obj.update(msg.encode())
    return int.from_bytes(h_obj.digest(), 'big')

a = -3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
p = 2^256 - 2^224 + 2^192 + 2^96 - 1

E = EllipticCurve(GF(p), [a, b])

G = E(48439561293906451759052585252797914202762949526041747995844080717082404635286, 36134250956749795798585127919587881956611106672985015071877198253568414405109)

io = remote(IP, PORT)

_ = io.sendlineafter(b"command:\r\n>", b"show")
Q = E(re.findall(b"\d+", io.recvline().strip())[1:])

_ = io.sendlineafter(b"command:\r\n>", b"sign")
_ = io.sendlineafter(b"sign:\r\n>", b"ls")
tmp = re.findall(b"\d+", io.recvline().strip())
R = E(tmp[:-1])
s = int(tmp[-1])

cmd = "cat flag"
new_R = G * hash(cmd) - (s * G - Q)
payload = str(new_R[0]) + '|' + str(new_R[1]) + '|' + str(s) + '|' + str(cmd)

_ = io.sendlineafter(b"command:\r\n>", b"run")
_ = io.sendlineafter(b"sig:\r\n>", payload)

io.interactive()

# flag{d1d_you_f1nd_chakraborty_mehta}