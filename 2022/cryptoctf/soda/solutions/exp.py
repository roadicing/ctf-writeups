#!/usr/bin/env python3

import re
from pwn import *
from Crypto.Util.number import bytes_to_long

IP = "01.cr.yp.toc.tf"
PORT = 37711

CRY = "Long Live Crypto :))"
m = bytes_to_long(CRY.encode('utf-8'))

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", "t")
io.sendlineafter("soda: \n", str(-m))
sd = int(re.findall(b"\d+", io.recvline())[0])

io.sendlineafter("[Q]uit\n", "v")
io.sendlineafter("verify: \n", str(sd))

io.interactive()

# CCTF{f4cToriZat!On__5Tt4cK_0n_4_5i9na7urE!}