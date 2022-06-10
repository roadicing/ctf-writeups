#!/usr/bin/env sage

# section 5.2, https://eprint.iacr.org/2021/1160.pdf

import itertools
from Crypto.Util.number import long_to_bytes, inverse

N = 144256630216944187431924086433849812983170198570608223980477643981288411926131676443308287340096924135462056948517281752227869929565308903867074862500573343002983355175153511114217974621808611898769986483079574834711126000758573854535492719555861644441486111787481991437034260519794550956436261351981910433997
e = 3707368479220744733571726540750753259445405727899482801808488969163282955043784626015661045208791445735104324971078077159704483273669299425140997283764223932182226369662807288034870448194924788578324330400316512624353654098480234449948104235411615925382583281250119023549314211844514770152528313431629816760072652712779256593182979385499602121142246388146708842518881888087812525877628088241817693653010042696818501996803568328076434256134092327939489753162277188254738521227525878768762350427661065365503303990620895441197813594863830379759714354078526269966835756517333300191015795169546996325254857519128137848289
ct = (123436198430194873732325455542939262925442894550254585187959633871500308906724541691939878155254576256828668497797665133666948295292931357138084736429120687210965244607624309318401630252879390876690703745923686523066858970889657405936739693579856446294147129278925763917931193355009144768735837045099705643710, 47541273409968525787215157367345217799670962322365266620205138560673682435124261201490399745911107194221278578548027762350505803895402642361588218984675152068555850664489960683700557733290322575811666851008831807845676036420822212108895321189197516787046785751929952668898176501871898974249100844515501819117)

a = N + 1
b = N^2 - N + 1

def add(P, Q, mod):
    m, n = P
    p, q = Q
    if p is None:
        return P
    if m is None:
        return Q
    if n is None and q is None:
        x = m * p % mod
        y = (m + p) % mod
        return (x, y)
    if n is None and q is not None:
        m, n, p, q = p, q, m, n
    if q is None:
        if (n + p) % mod != 0:
            x = (m * p + 2) * inverse(n + p, mod) % mod
            y = (m + n * p) * inverse(n + p, mod) % mod
            return (x, y)
        elif (m - n ** 2) % mod != 0:
            x = (m * p + 2) * inverse(m - n ** 2, mod) % mod
            return (x, None)
        else:
            return (None, None)
    else:
        if (m + p + n * q) % mod != 0:
            x = (m * p + (n + q) * 2) * inverse(m + p + n * q, mod) % mod
            y = (n * p + m * q + 2) * inverse(m + p + n * q, mod) % mod
            return (x, y)
        elif (n * p + m * q + 2) % mod != 0:
            x = (m * p + (n + q) * 2) * inverse(n * p + m * q + 2, mod) % mod
            return (x, None)
        else:
            return (None, None)

def do_power(P, a, mod):
    res = (None, None)
    t = P
    while a > 0:
        if a % 2:
            res = add(res, t, mod)
        t = add(t, t, mod)
        a >>= 1
    return res

# https://github.com/defund/coppersmith/blob/master/coppersmith.sage
load("coppersmith.sage")

P.<p_plus_q, k> = PolynomialRing(Zmod(e), "p_plus_q, k")
f = k * (p_plus_q^2 + a * p_plus_q + b) + 1

res = small_roots(f, [2^513, 2^400], m=3, d=4)[0]
p_plus_q, k = Integer(res[0]), Integer(res[1])

p = var('p')
q = var('q')
ans = solve([p + q == p_plus_q, p * q == N], p, q)

p = ans[0][0].rhs()
q = ans[0][1].rhs()

phi = Integer((p^2 + p + 1) * (q^2 + q + 1))
d = inverse(e, phi)

pt = do_power(ct, d, N)
print(long_to_bytes(pt[0]))
print(long_to_bytes(pt[1]))

# pbctf{I_love_to_read_crypto_papers_and_implement_the_attacks_from_them}
