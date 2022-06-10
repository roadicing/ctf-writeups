#!/usr/bin/env sage

import string
from pwn import *

ALLOWED_CHARS = string.ascii_lowercase + string.digits + "_"
P = len(ALLOWED_CHARS)

INT_TO_CHAR = {}
CHAR_TO_INT = {}
for _i, _c in enumerate(ALLOWED_CHARS):
    INT_TO_CHAR[_i] = _c
    CHAR_TO_INT[_c] = _i

A_list, b_list = [], []

IP = b"139.162.61.222"
PORT = 13371

io = remote(IP, PORT)

for _ in range(2022):
    _ = io.sendline(b"A" * 16)
    shares = eval(io.recvline().strip())
    M = matrix(GF(P), [[CHAR_TO_INT[j] for j in i] for i in shares])
    M_0, M_1, M_2 = M[:, :16], M[:, 16:32], vector(M[:, 32])
    if M_1.rank() < 16:
        v = M_1.left_kernel().matrix()[0]
        A_list.append(v * M_0)
        b_list.append(v * M_2)
        if len(A_list) == 16:
            break

A, b = matrix(GF(P), A_list), vector(GF(P), b_list)
res = A.solve_right(b)

password = "".join([INT_TO_CHAR[i] for i in res])
_ = io.sendline(password.encode())

io.interactive()

# TetCTF{m0r3_sh4r3s____m0r3_m0r3_m0r3_fun}