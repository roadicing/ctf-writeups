#!/usr/bin/env python3

import re
from pwn import *
from hashlib import sha256
from Crypto.Util.number import inverse

IP = b"pwnable.org"
PORT = 23334

N = 5**129 - 1

def get_r_s(io, m_0, m_1):
    _ = io.sendafter(b"> ", b'1')
    _ = io.sendafter(b"> ", m_0)
    _ = io.sendafter(b"> ", str(len(m_1)).encode())
    _ = io.sendafter(b"> ", m_1)
    r, s = re.findall(b"[(](.*)[)]", io.recvline().strip())[0].split(b', ')
    return (r, s)

io = remote(IP, PORT)

m_0 = b'a' * 10
m_1 = b"roadicing"

r_0, s_0 = get_r_s(io, m_0, m_1)
r_1, s_1 = get_r_s(io, m_0, m_1[::-1])

h_0 = int(sha256(m_0 + m_1).hexdigest(), 16)
h_1 = int(sha256(m_0 + m_1[::-1]).hexdigest(), 16)

k_0 = ((int(s_1, 16) - int(s_0, 16)) % N * inverse(h_1 - h_0, N)) % N
k_1 = (int(s_0, 16) - (h_0 * k_0) - int(m_0, 16)) % N

assert ((h_0 * k_0 + int(m_0, 16) + k_1) % N) == int(s_0, 16)
assert ((h_1 * k_0 + int(m_0, 16) + k_1) % N) == int(s_1, 16)

_ = io.sendafter(b"> ", b'3')
_ = io.recvuntil(b"Give a signature with m0 = ")
flag_m_0 = io.recvline().split(b' ')[0]
flag_m_1 =  b"show_me_flag"

flag_h = int(sha256(flag_m_0 + flag_m_1).hexdigest(), 16)
flag_s = hex((flag_h * k_0 + int(flag_m_0, 16) + k_1) % N)[2:].upper().encode()

p = process(b"./gene")

r_2, s_2 = get_r_s(p, m_0, m_1)
r_3, s_3 = get_r_s(p, m_0, m_1[::-1])

h_2 = int(sha256(m_0 + m_1).hexdigest(), 16)
h_3 = int(sha256(m_0 + m_1[::-1]).hexdigest(), 16)

k_2 = ((int(s_3, 16) - int(s_2, 16)) % N * inverse(h_3 - h_2, N)) % N
k_3 = (int(s_2, 16) - (h_2 * k_2) - int(m_0, 16)) % N

assert ((h_2 * k_2 + int(m_0, 16) + k_3) % N) == int(s_2, 16)
assert ((h_3 * k_2 + int(m_0, 16) + k_3) % N) == int(s_3, 16)

flag_r, _ = get_r_s(p, hex(int(flag_m_0, 16) + k_1 - k_3)[2:].upper(), m_1)

_ = io.sendafter(b"> ", flag_r)
_ = io.sendafter(b"> ", flag_s)

io.interactive()

# flag{TTAUUTCAGUGUGGTTGAAUAUAT}