#!/usr/bin/env sage

import re
from pwn import *
from tqdm import tqdm

IP = "01.cr.yp.toc.tf"
PORT = 17331

p = 2 ** 1024 - 2 ** 234 - 2 ** 267 - 2 ** 291 - 2 ** 403 - 1

io = remote(IP, PORT)

s = 1
for _ in tqdm(range(1024)):
    io.sendlineafter("[Q]uit\n", "t")
    s <<= 1
    g = Mod(4, p).nth_root(s)
    io.sendlineafter("integer: \n", str(g))
    res = io.recvline()
    if b"CCTF{" in res:
        print(res)
        break
    else:
        t = int(re.findall(b"\d+", res)[0])
        if t == 0:
            s += 1

# CCTF{h0W_iZ_h4rD_D15crEt3_lO9ar!Thm_c0nJec7ur3?!}