#!/usr/bin/env sage

# https://neuromancer.sk/std/other/JubJub

from Crypto.Util.number import long_to_bytes

P = (2021000018575600424643989294466413996315226194251212294606, 1252223168782323840703798006644565470165108973306594946199)
Q = (2022000008169923562059731170137238192288468444410384190235, 1132012353436889700891301544422979366627128596617741786134)
R = (2023000000389145225443427604298467227780725746649575053047, 4350519698064997829892841104596372491728241673444201615238)
enc = (3419907700515348009508526838135474618109130353320263810121, 5140401839412791595208783401208636786133882515387627726929)

def to_weierstrass(a, d, x, y):
	return ((5 * a + a * y - 5 * d * y - d) / (12 - 12 * y), (a + a * y - d * y -d) / (4 * x - 4 * x * y))

if __name__ == "__main__":
    PR.<a, d> = PolynomialRing(ZZ)

    fs = []
    for (x, y) in [P, Q, R, enc]:
        fs += [(a * x^2 + y^2 - d * x^2 * y^2 - 1)]

    I = Ideal(fs)
    p = I.groebner_basis()[-1]
    p = factor(p)[-1][0]

    I = I.change_ring(PR.change_ring(GF(p)))
    res = I.variety()[0]
    a, d = res[a], res[d]

    K = GF(p)
    E = EllipticCurve(K, (K(-1 / 48) * (a^2 + 14 * a * d + d^2), K(1 / 864) * (a + d) * (-a^2 + 34 * a * d - d^2)))

    print(factor(E.order()))

    wP = E(to_weierstrass(K(a), K(d), K(P[0]), K(P[1])))
    wenc = E(to_weierstrass(K(a), K(d), K(enc[0]), K(enc[1])))

    m = discrete_log(wenc, wP, wP.order(), operation = '+')
    FLAG = b"ASIS{" + long_to_bytes(m) + b'}'
    print(FLAG)

# ASIS{MoN7g0m3ry_EdwArd5_cuRv3}