#!/usr/bin/env sage

'''
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Hey math experts, in this challenge we will deal with the numbers   |
|  those are the sum of two perfect square, now try hard to find them! |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Generating the `n', please wait...
| Options:
|	[G]et the n
|	[S]olve the challenge!
|	[Q]uit
G
| n = 1862693230794949389855883968594281958401397908074388971118436793951758841
| Options:
|	[G]et the n
|	[S]olve the challenge!
|	[Q]uit
S
| Send your pair x, y here:
'''

import re
from pwn import *

IP = "05.cr.yp.toc.tf"
PORT = 37331

io = remote(IP, PORT)

io.sendlineafter("[Q]uit\n", "G")
n = int(re.findall(b"\d+", io.recvline())[0])

x, y = two_squares(n)

io.sendlineafter("[Q]uit\n", "S")
io.sendlineafter("here:", f"{x}, {y}")

io.interactive()

# CCTF{3Xpr3sS_4z_Th3_sUm_oF_7w0_Squ4rE5!}