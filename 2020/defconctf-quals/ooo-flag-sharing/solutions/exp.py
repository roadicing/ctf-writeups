#!/usr/bin/env python3

from pwn import *
from math import gcd
from Crypto.Util.number import inverse, isPrime

IP = b"ooo-flag-sharing.challenges.ooo"
PORT = 5000

def func_1(io, secret, num):
    io.sendlineafter(b"Choice: ", b'1')
    io.sendlineafter(b"Enter secret to share: ", secret)
    _ = io.recvuntil(b"Your secret's ID is: ")
    secret_id = io.recvline().strip()
    io.sendlineafter(b"Number of shares to make: ", str(num).encode())
    _ = io.recvuntil(b"Your shares are: ")
    shares = eval(io.recvline().strip())
    return secret_id, shares

def func_2(io, secret_id, shares):
    io.sendlineafter(b"Choice: ", b'2')
    io.sendlineafter(b"Enter the secret's ID: ", secret_id)
    io.sendlineafter(b"Enter your shares of the secret: ", str(shares).encode())
    _ = io.recvuntil(b"Your secret is: ")
    secret = io.recvline().strip()
    secret = eval(secret)
    return secret

def func_3(io):
    io.sendlineafter(b"Choice: ", b'3')
    io.recvuntil(b"Our secret's ID is: ")
    secret_id = io.recvline().strip()
    io.recvuntil(b"Your shares are: ")
    shares = eval(io.recvline().strip())
    return secret_id, shares

def func_4(io, secret_id, shares):
    io.sendlineafter(b"Choice: ", b'4')
    io.sendlineafter(b"Enter the secret's ID: ", secret_id)
    io.sendlineafter(b"Enter your shares of the secret: ", str(shares))
    res = io.recvline()
    return res.startswith(b"Congrats!")

def recover_P(io):
    input_a = b'~' * 40
    input_b = b'~' * 41
    secret_id, shares = func_1(io, input_a, 5)
    secret_a = func_2(io, secret_id, shares)
    secret_id, shares = func_1(io, input_b, 5)
    secret_b = func_2(io, secret_id, shares)
    kp = int.from_bytes(input_a, 'big') - int.from_bytes(secret_a, 'little')
    gp = int.from_bytes(input_b, 'big') - int.from_bytes(secret_b, 'little')
    P = gcd(kp, gp)
    if not isPrime(P):
        for i in range(2, 100, 2):
            if isPrime(P // i):
                P = P // i
                break
    return P

def recover_m_4(io, secret_id, shares, P):
    known_idx = [share[0] for share in shares]
    for a in range(1, 100):
        for b in range(a + 1, 100):
            if (a in known_idx) or (b in known_idx):
                continue
            m_4 = int.from_bytes(func_2(io, secret_id, [(a, 0), (b, 0), (known_idx[0], 0), (known_idx[1], 0), (known_idx[2], 1)]), 'little')
            token = func_4(io, secret_id, shares[:-1] + [(shares[2][0], (shares[2][1] + (1 << 32) * inverse(m_4, P)) % P)])
            if token:
                return m_4

def binary_search_x(io, secret_id, shares, P, m_4):
    low = 0
    high = P >> 32
    while low <= high:
        x = (low + high) // 2
        token = func_4(io, secret_id, shares[:-1] + [(shares[2][0], (shares[2][1] + (x << 32) * inverse(m_4, P)) % P)])
        if token:
            low = x + 1
        else:
            high = x - 1
    return x

io = remote(IP, PORT)

io.sendlineafter(b"Username: ", b"roadicing")
secret_id, shares = func_3(io)

P = recover_P(io)
m_4 = recover_m_4(io, secret_id, shares, P)
x = binary_search_x(io, secret_id, shares, P, m_4)

FLAG = b"OOO{" + (P - (x << 32)).to_bytes(32, 'little')[4:]
print(FLAG)

# OOO{ooo_c4nt_ke3p_secr3ts!}