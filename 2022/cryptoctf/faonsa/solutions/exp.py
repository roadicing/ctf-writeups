#!/usr/bin/env python3

from pwn import *

IP = "06.cr.yp.toc.tf"
PORT = 31117

MSG = b"4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :P"

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", 'a')
io.sendlineafter("like: 5, 12, ...\n", '0, 0')

io.sendlineafter("[Q]uit\n", 's')
io.sendlineafter("sign: \n", b'\x00' + MSG)
sig = re.findall(b"\d+", io.recvline())

io.sendlineafter("[Q]uit\n", 'v')
io.sendlineafter("verify: ", b','.join(sig))

io.interactive()

# CCTF{n3W_4t7aCk_8y_fAuL7_!nJ3cT10N_oN_p!!!}