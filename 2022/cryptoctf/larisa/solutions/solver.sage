#!/usr/bin/env sage

l, e = 128, 65537
SG = SymmetricGroup(l)

C = eval(open("enc.txt", "r").read().strip())

M = [list((SG(i)^inverse_mod(e, SG(i).multiplicative_order())).tuple()) for i in C]

for r in range(l):
    for s in range(l):
        FLAG = bytes([M[i][(i * r + s) % l] for i in range(l)])
        if b"CCTF{" in FLAG:
            print(FLAG)
            exit()

# CCTF{pUbliC_k3y_crypt0graphY_u5in9_rOw-l4t!N_5quAr3S!}