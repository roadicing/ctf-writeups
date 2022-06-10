#!/usr/bin/env sage

import re
from pwn import *
from tqdm import tqdm

taps = [60, 58, 54, 52, 48, 47, 45, 43, 38, 36, 32, 28, 22, 21, 13, 9, 8, 5, 2, 0]
n = 64

N = 2^30 + 2^29

IP = b"mc.ax"
PORT = 31669

M = matrix(GF(2), n - 1, 1)
M = M.augment(identity_matrix(GF(2), n - 1))
v = vector(GF(2), n)
for i in taps:
    v[i] = 1

M = M.stack(v)

io = remote(IP, PORT)
io.sendlineafter(b"2^31:", str(N).encode())

idx_offset = 0
idx_list = []
total_attempts = 0
for _ in tqdm(range(1023)):
    io.sendlineafter(b"Enter your command (R,F):", b"R")
    attempts = int(re.findall(r"\d+", io.recvline().decode())[0])
    if attempts > 1:
        for i in range(attempts - 1):
            idx_list.append(idx_offset + 31)
            idx_list.append(idx_offset + 30)
            idx_offset += 32
    idx_offset += 32
    total_attempts += attempts
    if len(idx_list) >= n:
        break

outputs = [[1] + [0] * (n - 1)]
Q = identity_matrix(GF(2), n)
for i in range(total_attempts * 32):
    Q *= M
    outputs.append(Q[0])

A = matrix(GF(2), [outputs[idx] for idx in idx_list])
b = vector(GF(2), [1] * len(idx_list))
res = A.solve_right(b)

key = int(''.join(list(map(str, res)))[::-1], 2)

io.sendlineafter(b"Enter your command (R,F):", b"F")
io.sendlineafter(b"what was my seed?", str(key).encode())

io.interactive()

# dice{so-many-numbers-got-rejected-on-valentines-day-1cc16ff5b20d6be1fbd65de0d234608c}