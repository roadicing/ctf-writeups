#!/usr/bin/env sage

import re
from pwn import *
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

IP = b"flu.xxx"
PORT = 20075

n = 128
m = 384

def lfsr(state):
    mask   = (1 << 384) - (1 << 377) + 1
    newbit = bin(state & mask).count('1') & 1
    return (state >> 1) | (newbit << 383)

def rev_lfsr(state):
    mask   = (1 << 384) - (1 << 376) 
    newbit = bin(state & mask).count('1') & 1
    return ((state << 1) | newbit) & ((1 << 384) -1)

io = remote(IP, PORT)

q = int(re.findall(b"\d+", io.recvline())[0])
pk = eval(io.recvline().strip())
pk = [(vector(Zmod(q), i), Zmod(q)(j)) for i, j in pk]
_ = io.recvline()

c_list = []
while True:
    res = io.recvline().strip()
    if b"Your message bit:" in res:
        break
    c_list.append(eval(res))

state_bin = ''
for i in tqdm(range(384)):
    if i == 0:
        _ = io.sendline(b'1')
    else:
        _ = io.sendlineafter(b"Your message bit: \n", b'1')
    res = io.recvline()
    if b'Success!' in res:
        state_bin += '1'
    else:
        state_bin += '0'

state = int(state_bin[::-1], 2)

for _ in range(384 + len(c_list)):
    state = rev_lfsr(state)

flag_bin = ''
for i in range(len(c_list)):
    c = [vector([0 for _ in range(n)]), 0]
    for j in range(384):
        if (state >> j) & 1 == 1:
            c[0] += vector(pk[j][0])
            c[1] += pk[j][1]
    flag_bin += str((c_list[i][1] - c[1]) // (q >> 1))
    state = lfsr(state)

FLAG = long_to_bytes(int(flag_bin, 2))

print(FLAG)

# flag{your_fluxmarket_stock_may_shift_up_now}
