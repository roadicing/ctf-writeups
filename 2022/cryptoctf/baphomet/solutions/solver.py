#!/usr/bin/env python3

from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor

ct = open("flag.enc", "rb").read()
known_pt_b64 = b64encode(b"CCTF{").decode()

key = b''.join([bytes([ct[i] ^ ord(known_pt_b64[i].swapcase())]) for i in range(6)])

pt = b''.join([bytes([ct[i] ^ key[i % len(key)]]).swapcase() for i in range(len(ct))])

FLAG = b64decode(pt)
print(FLAG)

# CCTF{UpP3r_0R_lOwER_17Z_tH3_Pr0bL3M}