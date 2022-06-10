#!/usr/bin/env sage

# https://www.math.uwaterloo.ca/~ajmeneze/publications/hyperelliptic.pdf

from Crypto.Util.number import long_to_bytes

F = GF(2**256)
P = PolynomialRing(F, 'u, v')
u, v = P.gens()
PP = PolynomialRing(F, 'w')
w = PP.gens()[0]

h = u^2 + u
f = u^5 + u^3 + 1
c = v^2 + h*v - f
f = f(u=w)
h = h(u=w)

def encode(plain):
    assert plain < 2**256
    x = F.fetch_int(plain)
    y, k = c(u=x, v=w).roots()[0]
    assert k == 1
    return w - x, y

def decode(c):
    x, y = c
    x = [i.integer_representation() for i in x]
    y = [i.integer_representation() for i in y]
    return x, y

def add(p1, p2):
    a1, b1 = p1
    a2, b2 = p2
    d1, e1, e2 = xgcd(a1, a2)
    d, c1, c2 = xgcd(d1, b1+b2+h)
    di = PP(1/d)
    a = a1*a2*di*di
    b = (c1*e1*a1*b2+c1*e2*a2*b1+c2*(b1*b2+f))*di
    b %= a
    while a.degree() > 2:
        a = PP((f-b*h-b*b)/a)
        b = (-h-b)%a
    a = a.monic()
    return a, b

def mul(p, k):
    if k == 1:
        return p
    else:
        tmp = mul(p, k//2)
        tmp = add(tmp, tmp)
        if k & 1:
            tmp = add(tmp, p)
        return tmp

q = 2
n = 256
FF = lambda x, y: y^2 + (x^2 + x)*y + x^5 + x^3 + 1

M_0 = len([(x, y) for x in GF(2) for y in GF(2) if FF(x, y) == 0]) + 1
M_1 = len([(x, y) for x in GF(4) for y in GF(4) if FF(x, y) == 0]) + 1

a_0 = M_0 - 1 - q
a_1 = (M_1 - 1 - q^2 + a_0^2) / 2

X = var('X')
gammas = list(map(lambda x: x.rhs(), solve([X^2 + a_0*X + (a_1 - 2 * 2) == 0], X)))

alpha_0 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[0]*X + q == 0], X)))[0]
alpha_1 = list(map(lambda x: x.rhs(), solve([X^2 - gammas[1]*X + q == 0], X)))[0]

N_n = int(abs(1 - alpha_0^n)^2 * abs(1 - alpha_1^n)^2)

e = 65537
d = int(inverse_mod(e, N_n))

ct = ([113832590633816699072296178013238414056344242047498922038140127850188287361982, 107565990181246983920093578624450838959059911990845389169965709337104431186583, 1], [60811562094598445636243277376189331059312500825950206260715002194681628361141, 109257511993433204574833526052641479730322989843001720806658798963521316354418])
Q = tuple(sum(F.fetch_int(c) * w^i for i, c in enumerate(j)) for j in ct)
pt = mul(Q, d)

FLAG = b"flag{" + long_to_bytes(decode(pt)[0][0]) + b"}"
print(FLAG)

# flag{1nTere5tinG_Hyp3re11iPtic_curv3}