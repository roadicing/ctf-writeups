#!/usr/bin/env python3

from pwn import *
import subprocess
import json
import hashlib
from fastecdsa.curve import P192 as Curve
from fastecdsa.point import Point
from secrets import randbits

def mod_hash(msg : bytes, R : Point) -> int:
    h = hashlib.sha256()
    h.update(len(msg).to_bytes(64, 'big'))
    h.update(msg)
    h.update(R.x.to_bytes(N//8, 'big'))
    h.update(R.y.to_bytes(N//8, 'big'))
    return int(h.hexdigest(), 16) % Curve.q

N = Curve.q.bit_length()
G = Curve.G

server_pubkey_share = Point(0x9532cae35947c6211c2f808145aa193f9773e591b03f3e1b, 0x3df6739646175efd21fe509d8b1f436fa4f6663b4eec9641, Curve)
client_privkey_share = 0xee669fa9dc3e12154d13ac6bc17d6c3b2291832dadd76746

IP = "very-frosty-ams3.nc.jctf.pro"
PORT = 4445

io = remote(IP, PORT)

io.recvuntil("Proof of Work:\n")
cmd = io.recvline().strip()
stamp = subprocess.getoutput(cmd)
io.sendlineafter("Your PoW: ", stamp)

io.recv()
io.sendline(json.dumps({"op": "sign"}))
public_nonce = json.loads(io.recvline().strip())['D']
client_nonce = public_nonce

m = b"roadicing"
payload = {
    "D": client_nonce,
    "msg": m.hex()
}
io.sendline(json.dumps(payload))
z = json.loads(io.recvline().strip())['z']

R = Point(int(client_nonce[0], 16), int(client_nonce[1], 16), Curve) * 2
c = mod_hash(m, R)

approx_server_privkey_share = int(z, 16) // c

for i in range(-500, 500):
    server_privkey_share = approx_server_privkey_share + i
    if server_privkey_share * G == server_pubkey_share:
        print("FOUND: " + hex(server_privkey_share))
        break

O = G - G
m = b"Gimme!"
z = mod_hash(m, O) * (server_privkey_share + client_privkey_share)
c = mod_hash(m, O)

payload = {
            "op": "verify",
            "z": hex(z)[2:],
            "c": hex(c)[2:],
            "m": m.hex()
}

io.close()
io = remote(IP, PORT)

io.recvuntil("Proof of Work:\n")
cmd = io.recvline().strip()
stamp = subprocess.getoutput(cmd)
io.sendlineafter("Your PoW: ", stamp)

io.recv()
io.sendline(json.dumps(payload))
io.interactive()

# justCTF{Elsa_was_here!}