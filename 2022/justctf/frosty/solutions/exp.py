#!/usr/bin/env python3

from pwn import *
import subprocess
import json
import hashlib
from fastecdsa.curve import P192 as Curve
from fastecdsa.point import Point

def mod_hash(msg : bytes, R : Point) -> int:
    h = hashlib.sha256()
    h.update(len(msg).to_bytes(64, 'big'))
    h.update(msg)
    h.update(R.x.to_bytes(N//8, 'big'))
    h.update(R.y.to_bytes(N//8, 'big'))
    return int(h.hexdigest(), 16) % Curve.q

N = Curve.q.bit_length()

G = Curve.G
O = G - G

pubkey = (hex(G.x)[2:], hex(G.y)[2:])
m = b"Gimme!"
z = c = mod_hash(m, O)

payload = {
    "op": "verify",
    "pubkey": pubkey,
    "z": hex(z)[2:],
    "c": hex(c)[2:],
    "m": m.hex()
}

IP = "frosty.nc.jctf.pro"
PORT = 4444

io = remote(IP, PORT)

io.recvuntil("Proof of Work:\n")
cmd = io.recvline().strip()
stamp = subprocess.getoutput(cmd)
io.sendlineafter("Your PoW: ", stamp)

io.recv()
io.sendline(json.dumps(payload))
io.interactive()

# 