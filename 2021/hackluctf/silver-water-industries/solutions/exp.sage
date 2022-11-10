#!/usr/bin/env sage

from pwn import *

IP = b"flu.xxx"
PORT = 20060

io = remote(IP, PORT)

N = int(io.recvline().strip())

ct_list = []
for _ in range(20):
    ct_list.append(eval(io.recvline().strip().replace(b' ', b', ')))

token = ''
for ct in ct_list:
    bin_str = ''
    for i in ct:
        if jacobi_symbol(i, N) == -1:
            bin_str += '1'
        else:
            bin_str += '0'
    token += chr(int(bin_str, 2))

io.sendline(token)
io.interactive()

# flag{Oh_NO_aT_LEast_mY_AlGORithM_is_ExpanDiNg}
