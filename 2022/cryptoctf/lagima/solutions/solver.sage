#!/usr/bin/env sage

from Crypto.Util.number import long_to_bytes

l = 313
SG = SymmetricGroup(l)

f = open("output.txt", "r").read().split('\n')
G, H = eval(f[0][4:]), eval(f[1][4:])

residues = []
moduli = []
for i, j in zip(G, H):
    residues += [discrete_log(SG(j), SG(i))]
    moduli += [SG(i).multiplicative_order()]

secret = crt(residues, moduli)
FLAG = b"CCTF{" + long_to_bytes(secret) + b"}"
print(FLAG)

# CCTF{3lGam4L_eNcR!p710n_4nD_L4T!n_5QuarS3!}