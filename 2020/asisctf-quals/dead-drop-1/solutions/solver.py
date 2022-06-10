#!/usr/bin/env sage

from Crypto.Util.number import *

f = open('flag.enc', 'rb')
p = int(f.readline().strip())
enc = eval(f.readline().strip().replace(b'L', b''))

l = len(enc)

'''
sage: factor(p)
19 * 113 * 2657 * 6823 * 587934254364063975369377416367
sage: factor(587934254364063975369377416367 - 1)
2 * 19 * 157 * 98547478103262483300264401
'''

p_0 = 587934254364063975369377416367
r = 157
t = (p_0 - 1) // r

dic = {}
for i in range(r):
    dic.update({pow(pow(3, t, p_0), i, p_0) : i})

M = []
b = []
for i in range(l):
    T = []
    for j in range(l):
        z_a = dic[pow(enc[i][0][j], t, p_0)]
        T.append(z_a)
    z_as = dic[pow(enc[i][1], t, p_0)]
    M.append(T)
    b.append(z_as)

M = Matrix(Zmod(r), M)
b = vector(Zmod(r), b)
res = M.solve_right(b)

FLAG = long_to_bytes(int(''.join([i for i in map(str, res)]), 2))
print(FLAG)

# ASIS{175_Lik3_Multivariabl3_LiNe4r_3QuA7i0n5}