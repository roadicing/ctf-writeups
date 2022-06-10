#!/usr/bin/env sage

from pwn import *

p = 50824208494214622675210983238467313009841434758617398532295301998201478298245257311594403096942992643947506323356996857413985105233960391416730079425326309

F = GF(p)
i = F(-1).sqrt()

T = ((1 + i * 2022) / (1 - i * 2022)).sqrt()

# See `formula.pdf` for more details.
def f(x):
    return (1 + x * T) / (1 + x / T)

IP = b"139.162.61.222"
PORT = 13374

io = remote(IP, PORT)
a, b, c = [int(io.recvline().strip()) for _ in range(3)]

fa, fb, fc = f(a), f(b), f(c)
_ = [io.sendline(str(i)) for i in [fa, fb, fc]]

io.interactive()

# TetCTF{1_just_l0v3_th3_un1t_c1rcl3_s0_much}