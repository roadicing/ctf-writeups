#!/usr/bin/env sage

from pwn import *

IP = "47.254.47.63"
PORT = 13337

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
a = 0
b = 3
order = 21888242871839275222246405745257275088548364400416034343698204186575808495617
G1 = (1, 2)

E = EllipticCurve(GF(p), [a, b])

def EE(P):
    return E(int(P[0]), int(P[1]))

if __name__ == "__main__":
    io = remote(IP, PORT)
    _ = [io.recvline() for _ in range(3)]

    PK = eval(io.recvline())

    PiC = EE(PK[0][4]) - 10 * EE(PK[0][3]) + 35 * EE(PK[0][2]) - 50 * EE(PK[0][1]) + 24 * EE(PK[0][0])
    PiCa = EE(PK[1][4]) - 10 * EE(PK[1][3]) + 35 * EE(PK[1][2]) - 50 * EE(PK[1][1]) + 24 * EE(PK[1][0])
    PiH = EE(G1)

    msg = str((PiC.xy(), PiCa.xy(), PiH.xy()))
    io.sendlineafter("now give me your proof\n", msg)

    io.interactive()

# rwctf{How_do_you_feel_about_zero_knowledge_proof?}