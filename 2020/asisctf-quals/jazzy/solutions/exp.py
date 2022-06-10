#!/usr/bin/env python3

import re
from pwn import *
from Crypto.Util.number import long_to_bytes

IP = b"76.74.178.201"
PORT = 31337

io = remote(IP, PORT)
_ = io.recv()

io.sendline('F')
ct = list(map(int, re.findall(b"\d+", io.recvline())))

io.sendline('P')
pubkey = int(re.findall(b"\d+", io.recvline())[0])

h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1
new_ct = (int(bin(ct[0])[2:] + '0' * h, 2), pow(ct[1], 2, pubkey))

io.sendline('D')
io.sendlineafter(b"decrypt: \n", str(new_ct))

pt = int(re.findall(b"\d+", io.recvline())[0])

FLAG = long_to_bytes(int(bin(pt)[2: -h], 2))
print(FLAG)

# ASIS{BlUM_G0ldwaS53R_cryptOsySt3M_Iz_HI9hlY_vUlNEr4bl3_70_CCA!?}