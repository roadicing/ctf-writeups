#!/usr/bin/env sage

import re
from pwn import *
from hashlib import sha1
from Crypto.Util.number import *

IP = "03.cr.yp.toc.tf"
PORT = 11137

def gen_smooth_prime(nbits, imbalance):
    p = int(2)
    while p.bit_length() < nbits - 2 * imbalance:
    	p *= getPrime(imbalance)
    rbits = (nbits - p.bit_length()) // 2
    while True:
    	r, s = [getPrime(rbits) for _ in '01']
    	_p = p * r * s
    	if _p.bit_length() < nbits: rbits += 1
    	if _p.bit_length() > nbits: rbits -= 1
    	if isPrime(_p + 1) and int(_p + 1).bit_length() == nbits:
    		p = _p + 1
    		return p

while True:
    io = remote(IP, PORT)

    io.sendlineafter("[Q]uit\n", "p")
    sig = int(re.findall(b"\d+", io.recvline())[0])

    p = gen_smooth_prime(1024, 16)
    q = gen_smooth_prime(1024, 16)
    n = p * q

    MSG = b'::. Can you forge any signature? .::'
    h = bytes_to_long(sha1(MSG).digest())

    try:
        e_p = discrete_log(Mod(h, p), Mod(sig, p))
        e_q = discrete_log(Mod(h, q), Mod(sig, q))
        e = crt([e_p, e_q], [p - 1, q - 1])
        assert gcd(e, (p - 1) * (q - 1)) == 1
        break
    except:
        io.close()
        continue

io.sendlineafter("[Q]uit\n", "g")
io.sendlineafter("e, p, q: \n", f"{e}, {p}, {q}")

_MSG = MSG[4:-4]
_h = bytes_to_long(sha1(_MSG).digest())

d = inverse_mod(e, (p - 1) * (q - 1))
_sig = pow(_h, d, n)

io.sendlineafter("[Q]uit\n", "s")
io.sendlineafter("message: \n", str(_sig))

io.interactive()

# CCTF{Unkn0wN_K3y_5h4rE_4t7aCk_0n_Th3_RSA!}