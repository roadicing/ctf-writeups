#!/usr/bin/env sage

from Crypto.Util.number import *

f = open('flag.enc', 'rb')
p = int(f.readline().strip())
enc = eval(f.readline().strip().replace(b'L', b''))

l = len(enc[0][0])

'''
sage: factor(p - 1)
2 * 103 * 397 * 14621 * 21622810159 * 52792444681 * 1553877481309 * 18616484120267152928623
'''

r = 397
t = (p - 1) // r

dic = {}
for i in range(r):
    dic.update({pow(pow(3, t, p), i, p) : i})

M = []
b = []
for i in range(l):
    T = []
    for j in range(l):
        z_a = dic[pow(enc[i][0][j], t, p)]
        T.append(z_a)
    z_as = dic[pow(enc[i][1], t, p)]
    M.append(T)
    b.append(z_as)

M = Matrix(Zmod(r), M)
b = vector(Zmod(r), b)
res = M.solve_right(b)

FLAG = b"ASIS{" + long_to_bytes(int(''.join([i for i in map(str, res)]), 2)) + b'}'
print(FLAG)

# ASIS{175_Lik3_Multivariabl3_LiNe4r_3QuA7i0n5}