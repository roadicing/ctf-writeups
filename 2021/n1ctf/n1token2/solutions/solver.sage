#!/usr/bin/env sage

from Crypto.Util.number import long_to_bytes

p = 251
e = [1, 20, 113, 149, 219]

y = list(bytes.fromhex("1d85d235d08dfa0f0593b1cfd41d3c98f2a542b2bf7a614c5d22ea787e326b4fd37cd6f68634d9bdf5f618605308d4bb16cb9b9190c0cb526e9b09533f19698b9be89b2e88ba00e80e44d6039d3c15555d780a6a2dbd14d8e57f1252334f16daef316ca692c02485684faee279d7bd926501c0872d01e62bc4d8baf55789b541358dfaa06d11528748534103a80c699a983c385e494a8612f4f124bd0b2747277182cec061c68197c5b105a22d9354be9e436c8393e3d2825e94f986a18bd6df9ab134168297c2e79eee5dc6ef15386b96b408b319f53b66c6e55b3b7d1a2a2930e9d34287b74799a59ab3f56a31ae3e9ffa73362e28f5751f79"))

P.<x> = PolynomialRing(GF(p))

M = [[] for _ in range(p - 1)]
b = []

for x_v in range(p - 1):
    f = (x + e[0] - y[x_v]) * (x + e[1] - y[x_v]) * (x + e[2] - y[x_v]) * (x + e[3] - y[x_v]) * (x + e[4] - y[x_v])
    coeff = f.coefficients(sparse = False)
    M[x_v] += [(coeff[1] * power_mod(x_v + 1, i, p)) % p for i in range(16 + 1)]
    M[x_v] += [(coeff[2] * power_mod(x_v + 1, i, p)) % p for i in range(32 + 1)]
    M[x_v] += [(coeff[3] * power_mod(x_v + 1, i, p)) % p for i in range(48 + 1)]
    M[x_v] += [(coeff[4] * power_mod(x_v + 1, i, p)) % p for i in range(64 + 1)]
    M[x_v] += [(coeff[5] * power_mod(x_v + 1, i, p)) % p for i in range(80 + 1)]
    b.append(p - coeff[0])

M = matrix(GF(p), M)
b = vector(GF(p), b)

res = M.solve_right(b)

SECRET = b''.join(map(lambda x: bytes([x]), res[1: 16 + 1]))

FLAG = "n1ctf{" + SECRET.hex() + "}"
print(FLAG)

# n1ctf{c5cc7404dc79e7a9d57ab19040a82f5a}