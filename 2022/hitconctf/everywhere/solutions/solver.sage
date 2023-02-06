#/usr/bin/env sage

'''
https://eprint.iacr.org/2011/590.pdf
'''

from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
import random
from tqdm import tqdm

n, q = 263, 128
T = 400

Zx.<x> = ZZ[]
def convolution(f, g):
    return (f * g) % (x^n - 1)

def balancedmod(f, q):
    g = list(((f[i] + q // 2) % q) - q // 2 for i in range(n))
    return Zx(g)  % (x^n - 1)

def randomdpoly(d1, d2):
    result = d1 * [1] + d2 * [-1] + (n - d1 - d2) * [0]
    random.shuffle(result)
    return Zx(result)

def invertmodprime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n - 1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    assert q.is_power_of(2)
    g = invertmodprime(f, 2)
    while True:
        r = balancedmod(convolution(g, f), q)
        if r == 1: return g
        g = balancedmod(convolution(g, 2 - r), q)

def keypair():
    while True:
        try:
            f = randomdpoly(61, 60)
            f3 = invertmodprime(f, 3)
            fq = invertmodpowerof2(f, q)
            break
        except Exception as e:
            pass
    g = randomdpoly(20, 20)
    publickey = balancedmod(3 * convolution(fq, g), q)
    secretkey = f
    return publickey, secretkey, g

def encode(val):
    poly = 0
    for i in range(n):
        poly += ((val % 3) - 1) * (x^i)
        val //= 3
    return poly

def encrypt(message, publickey):
    r = randomdpoly(18, 18)
    return balancedmod(convolution(publickey, r) + encode(message), q)

def handle(x):
    t = [ZZ(i) for i in x]
    dics = sorted(list(set(x[-n:])))
    assert len(dics) % 3 == 0
    for i in range(len(x)):
        if dics.index(x[i]) % 3 == 0:
            t[i] = -1
        elif dics.index(x[i]) % 3 == 1:
            t[i] = 0
        elif dics.index(x[i]) % 3 == 2:
            t[i] = 1
    return t

def decode(value):
    out = sum([(value[i] + 1) * 3 ^ i for i in range(len(value))])
    return out

def coeff(f):
    tmp = f.coefficients(sparse = False)
    return tmp + (n - len(tmp)) * [0]

def list_move_right(A, a):
    B = [i for i in A]
    for i in range(a):
        B.insert(0, B.pop())
    return B

def list_move_left(A, a):
    B = [i for i in A]
    for i in range(a):
        B.insert(len(B), B[0])
        B.remove(B[0])
    return B

def invertmodprime_with_poly(f,p,poly):
    T = Zx.change_ring(Integers(p)).quotient(poly)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2_with_poly(f,q,poly):
    assert q.is_power_of(2)
    g = invertmodprime_with_poly(f,2,poly)
    while True:
        r = balancedmod((g * f) % poly,q)
        if r == 1: return g
        g = balancedmod((g * (2 - r)) % poly,q)

output = open("output.txt", 'rb').read().split(b'\n')[:-1]

pks = []
cts = []
for data in tqdm(output):
    if data.startswith(b'key:  '):
        pks += [sage_eval(data.replace(b'key:  ', b'').decode(), locals={'x':x})]
    elif data.startswith(b'data: '):
        cts += [sage_eval(data.replace(b'data: ', b'').decode(), locals={'x':x})]

assert len(pks) == 400 and len(cts) == 400

mats = []
svs = []

d = 0
for idx in tqdm(range(T)):
    publickey = h = pks[idx]
    ct = cts[idx]
    hl = coeff(h)

    H0 = [hl[0]] + hl[1:][::-1]
    H = [H0]
    for i in range(1, len(hl)):
        H += [list_move_right(H0, i)]

    HM = matrix(H)
    poly = x^n - 1
    poly1 = x - 1
    poly2 = poly // poly1

    h_ = h % (poly // (x - 1))
    h__ = invertmodpowerof2_with_poly(h_, q, (poly // (x - 1)))
    _, u, v = xgcd(poly2.change_ring(Zmod(q)), poly1.change_ring(Zmod(q))) 
    h_inv = 1 + (x - 1) * v * (h__ - 1)
    h_inv = h_inv % poly
    hil = coeff(h_inv)

    HINV0 = [hil[0]] + hil[1:][::-1]
    HINV = [HINV0]
    for i in range(1, len(hil)):
        HINV += [list_move_right(HINV0, i)]

    HINVM = matrix(Zmod(q), HINV)
    C = vector(coeff(ct.change_ring(Zmod(q))))
    B = HINVM * C

    w = B * HINVM
    HTH = HINVM.T * HINVM
    av = vector([HTH[0][0]] + HTH[0][1:][::-1].list())
    s = d - B * B
    mat = [av[0]] + [2 * i for i in av.list()[1: n // 2 + 1]] + [-2 * i for i in w]
    mats += [mat]
    svs += [s]

M = matrix(Zmod(q), mats)
S = vector(Zmod(q), svs)
res = M.solve_right(S)

print(l2b(decode(handle(res[-n: ])))) #hitcon{ohno!y0u_broadc4st_t0o_much}