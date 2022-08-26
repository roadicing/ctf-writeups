#!/usr/bin/env python3

from pwn import *
from tqdm import tqdm

IP = "02.cr.yp.toc.tf"
PORT = 17113

io = remote(IP, PORT)

for i in tqdm(range(19)):
    z = (2**(i + 30)) - 1
    x = y = z**2
    io.sendlineafter("-bit: \n", f"{x}, {y}, {z}")
    res = io.recvline().decode()
    if "CCTF{" in res:
        print(res)
        break

# CCTF{4_diOpH4nT1nE_3Qua7i0n__8Y__Jekuthiel_Ginsbur!!}