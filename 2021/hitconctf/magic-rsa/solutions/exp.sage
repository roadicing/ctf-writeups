#!/usr/bin/env sage

from pwn import *
from hashlib import sha384
from Crypto.Util.number import long_to_bytes, bytes_to_long

IP = b"35.72.139.70"
PORT = 31337

def gen_vuln_p(bits):
    while True:
        p = 2
        while p.nbits() < bits:
            p *= random_prime(10^6)
        p += 1
        if is_prime(p):
            return p

def get_P(bits, factor_bits, magic_num):
    while True:
        p = gen_vuln_p(bits)
        p = ((magic_num << 248) // (p - 1) + 1) * (p - 1) + 1
        try:
            assert p >> (384 - 17 * 8) == magic_num
            assert is_prime(p)
            assert list(factor(p - 1))[-1][0].nbits() < factor_bits
        except:
            continue
        return p

def get_data_and_E(p):
    g = Integer(GF(p).multiplicative_generator())
    while True:
        data = power_mod(g, randint(1, 2^128), p)
        data_hash = bytes_to_long(sha384(long_to_bytes(data)).digest())
        if data_hash < p:
            try:
                e = discrete_log(Mod(data_hash, p), Mod(data, p))
            except:
                continue
            return (data, e)

io = remote(IP, PORT)

_ = io.recvuntil(b"Magic:")
magic_num = Integer(io.recvline().strip().decode(), 16)

p = get_P(240, 46, magic_num)

data, e = get_data_and_E(p)

assert power_mod(data, e, p) == bytes_to_long(sha384(long_to_bytes(data)).digest())

_ = io.sendlineafter(b"N:>", str(p).encode())
_ = io.sendlineafter(b"E:>", str(e).encode())
_ = io.sendlineafter(b"data:>", long_to_bytes(data).hex())

io.interactive()

# hitcon{Did_you@solve!this_with_smoooothness?}