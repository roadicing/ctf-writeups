#!/usr/bin/env python3

'''
[!] unintended solution.
just send the ciphertext back to get the expected plaintext since the encryption is not deterministic.
'''

import re
from pwn import *

IP = "162.55.188.246"
PORT = 31337

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", 'e')
io.recvuntil("C1 = ")

res = io.recvuntil("C2 = ")
res = res.split(b'\n')[:-1]

C1 = []
for i in res:
    C1 += list(eval(b','.join(re.findall(b'\d+', i)).decode()))

res = io.recvuntil("Options:")
res = res.split(b'\n')[:-1]

C2 = []
for i in res:
    C2 += list(eval(b','.join(re.findall(b'\d+', i)).decode()))

io.sendlineafter("[Q]uit\n", 'd')
io.sendlineafter("C1: \n", str(C1)[1: -1])
io.sendlineafter("C2: \n", str(C2)[1: -1])

res = io.recvuntil("is:\n")
res = res.split(b'\n')[:-1]

pt = []
for i in res:
    pt += list(eval(b','.join(re.findall(b'\d+', i)).decode()))

FLAG = bytes(pt)
print(FLAG)

# ASIS{e35Y_puBl!c_kEy_cRypTOsYst3M_84SeD_0n_Ma7ricEs!!}