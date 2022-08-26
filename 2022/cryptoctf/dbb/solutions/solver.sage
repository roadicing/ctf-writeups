#!/usr/bin/env sage

import itertools
from Crypto.Util.number import long_to_bytes

N = 34251514713797768233812437040287772542697202020425182292607025836827373815449
P = (10680461779722115247262931380341483368049926186118123639977587326958923276962, 4003189979292111789806553325182843073711756529590890801151565205419771496727)

F = IntegerModRing(N)

a = 31337
b = (P[1]^2 - P[0]^3 - a * P[0]) % N

'''
sage: factor(n)
11522256336953175349 * 14624100800238964261 * 203269901862625480538481088870282608241
'''
factor_list = [11522256336953175349, 14624100800238964261, 203269901862625480538481088870282608241]

order_list = []
res_list = [[] for _ in range(len(factor_list))]
for i in range(len(factor_list)):
    p = factor_list[i]
    E = EllipticCurve(GF(p), [a, b])
    P_n = E(P[0] % p, P[1] % p)
    G_n_list = E.lift_x(7331, all = True)
    order_list += [G_n_list[0].order()]
    for G_n in G_n_list:
        res_list[i] += [discrete_log(P_n, G_n, operation = '+')]

res_list = list(itertools.product(*res_list))
for i in res_list:
    m = crt(list(i), order_list)
    FLAG = long_to_bytes(m)
    if b"CCTF{" in FLAG:
        print(FLAG)

# CCTF{p0Hl!9_H31LmaN_4tTackin9!}