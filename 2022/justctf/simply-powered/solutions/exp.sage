#!/usr/bin/env sage

import re
from pwn import *
from tqdm import tqdm

IP = "nc simply-powered-nyc3.nc.jctf.pro"
PORT = 4444

io = remote(IP, PORT)

for _ in tqdm(range(100)):
    io.recvuntil("e =  ")
    e = int(io.recvline().strip())
    io.recvuntil("p =  ")
    p = int(io.recvline().strip())
    io.recvline()
    R = eval(io.recvline())
    R = R.change_ring(GF(p))
    M = R^inverse_mod(e, GL(R.dimensions()[0], p).order())
    ans = sum(M.change_ring(ZZ).list())
    io.sendlineafter("sum: ", str(ans))

io.interactive()

# 
