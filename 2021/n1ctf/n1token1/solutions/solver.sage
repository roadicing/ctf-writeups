#!/usr/bin/env python3

import re
from Crypto.Util.number import long_to_bytes, sieve_base

def rabin_decrypt(ct, sk, N):
    p, q = sk
    inv_p = inverse_mod(p, q)
    inv_q = inverse_mod(q, p)
    m_p = power_mod(ct, (p + 1) // 4, p)
    m_q = power_mod(ct, (q + 1) // 4, q)
    a = (inv_p * p * m_q + inv_q * q * m_p) % N
    b = N - a
    c = (inv_p * p * m_q - inv_q * q * m_p) % N
    d = N - c
    return [a, b, c, d]

f = open("output.txt", "r")

N = Integer(re.findall(r"\d+", f.readline())[0])
token_list = [Integer(re.findall(r"\d+", f.readline())[1]) for _ in range(920)]

token_square_list = [power_mod(i, 2, N) for i in token_list]

SIZE_0 = 64
SIZE_1 = 920

M = identity_matrix(ZZ, SIZE_0) * N
M = M.stack(vector(ZZ, token_square_list[: SIZE_0]))

res = M.LLL()

X_list = []
X_list.append(res[1][0])

c_square = (token_square_list[0] * inverse_mod(X_list[0], N)) % N

X_list = X_list + [Integer((token_square_list[i] * inverse_mod(c_square, N)) % N) for i in range(1, SIZE_1)]

prime_list = []
for prime in sieve_base:
    for X in X_list:
        if X % prime == 0:
            prime_list.append(prime)
            break

A = list(matrix(ZZ, 920, 920))

for i in range(len(X_list)):
    for prime, exponent in list(factor(X_list[i])): 
        A[i][prime_list.index(prime)] = exponent

A = matrix(GF(2), A)

res_list = A.left_kernel().basis()

res = 0
for i in range(len(res_list)):
    if list(res_list[i]).count(1) % 2 == 0:
        res = res_list[i]
        break

cnt = list(res).count(1)

token_square_pro = 1
X_pro = 1
for i in range(SIZE_1):
    if res[i] == 1:
        token_square_pro *= token_list[i]
        X_pro *= X_list[i]

X_pro_sqrt = X_pro.nth_root(2, True)[0]

k = (((token_square_pro * inverse_mod(X_pro_sqrt, N)) % N) * power_mod(c_square, -(cnt // 2), N)) % N

p = gcd(k - 1, N)
q = gcd(k + 1, N)

assert is_prime(p) and is_prime(q)
assert p * q == N

ct_list = rabin_decrypt(c_square, (p, q), N)

for ct in ct_list:
    d = inverse_mod(65537, (p - 1) * (q - 1))
    pt = power_mod(ct, d, N)
    FLAG = long_to_bytes(pt)
    if FLAG.startswith(b"n1ctf"):
        print(FLAG)

# n1ctf{b9e7d419-0df8-438a-9120-efdf3ddf155f}