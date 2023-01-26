#!/usr/bin/env sage

p = 361550014853497117429835520396253724671
bits = 128

def cgl(m):
    n = int('0' + m.encode('hex'), 16)
    F.<i> = GF(p ** 2, modulus = x ** 2 + 1)
    E = EllipticCurve(F, [1, 0])
    P, Q = (E.lift_x(x) for x in (i, 0))
    for b in reversed(range(8 * len(m) + 1)):
        if n >> b & 1:
            P, Q = Q, P
        phi = E.isogeny(P)
        E = phi.codomain()
        f = E.torsion_polynomial(2) // (polygen(F) - phi(Q).xy()[0])
        P, Q = (E.lift_x(x) for x in sorted(f.roots(multiplicities = False)))
        sys.stdout.write('.'); sys.stdout.flush()

    r = ZZ(E.j_invariant().polynomial()(34192034817997177)) & (1 << bits) - 1
    return '{{:0{:d}x}}'.format(bits // 4).format(r).decode('hex')

s1 = raw_input().strip().decode('hex')
s2 = raw_input().strip().decode('hex')

if s1 == s2:
    print('no'); exit()

if cgl(s1) != cgl(s2):
    print('\nno no'); exit()

print('\n' + open('flag.txt').read().strip())

