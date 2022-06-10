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

R = PolynomialRing(GF(P), x, 32)
xs = R.gens()

TABLE = []
for i in xs:
    for j in xs:
        if (i * j) not in TABLE:
            TABLE.append(i * j)

TABLE = TABLE + list(xs)

IP = b"139.162.61.222"
PORT = 13372

io = remote(IP, PORT)

A_list = []
b_list = []
for _ in range(18):
    _ = io.sendline(b"A" * 16)
    shares = eval(io.recvline().strip())
    M = matrix(GF(P), [[CHAR_TO_INT[j] for j in i] for i in shares])
    for row in M:
        poly = sum([x * y for x, y in zip(row[: 32], xs)])
        poly = ((poly - row[-1]) * (poly - (row[-1] - P // 2) % P))
        coeffs = [poly.monomial_coefficient(i) for i in TABLE]
        A_list.append(coeffs)
        b_list.append(-poly.constant_coefficient())

A, b = matrix(GF(P), A_list), vector(GF(P), b_list)
res = A.solve_right(b)

password = "".join([INT_TO_CHAR[i] for i in res[-32:]])
_ = io.sendline(password.encode())

io.interactive()

# TetCTF{but_th3_m4st3r_sh4re_1s_n0t_fun_4t_4ll}