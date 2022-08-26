#!/usr/bin/env python3

'''
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Hello, now we are finding the integer solution of two divisibility  |
|  relation. In each stage send the requested solution. Have fun :)    |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| We know (ax + by) % q = 0 for any (a, b) such that (ar + bs) % q = 0
| and (q, r, s) are given!
| Options:
|	[G]et the parameters
|	[S]end solution
|	[Q]uit
G
| q = 173096576609794944398725162420449153011
| r = 121518776449871976553423468189235628032
| s = 128351442423623967120223371762403433155
| Options:
|	[G]et the parameters
|	[S]end solution
|	[Q]uit
S
| please send requested solution like x, y such that y is 12-bit:
'''

import re
from pwn import *
from Crypto.Util.number import inverse

IP = "04.cr.yp.toc.tf"
PORT = 13777

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", "G")
q, r, s = [int(re.findall(b"\d+", io.recvline())[0]) for _ in range(3)]

io.sendlineafter("[Q]uit\n", "S")
while True:
    res = io.recvline().decode()
    op, bit_num = res[53], int(re.findall("\d+", res)[0])

    if op == 'x':
        x = (2**bit_num) - 1
        y = (x * inverse(r, q) * s) % q
    else:
        y = (2**bit_num) - 1
        x = (y * inverse(s, q) * r) % q

    io.sendline(f"{x}, {y}")
    res = io.recvline().decode()
    if "CCTF{" in res:
        print(res)
        break

# CCTF{f1nDin9_In7Eg3R_50Lut1Ons_iZ_in73rEStIn9!}