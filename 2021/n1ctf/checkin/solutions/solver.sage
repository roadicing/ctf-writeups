#!/usr/bin/env sage

from Crypto.Util.number import long_to_bytes

N = 124592923216765837982528839202733339713655242872717311800329884147642320435241014134533341888832955643881019336863843062120984698416851559736918389766033534214383285754683751490292848191235308958825702189602212123282858416891155764271492033289942894367802529296453904254165606918649570613530838932164490341793
ct = 119279592136391518960778700178474826421062018379899342254406783670889432182616590099071219538938202395671695005539485982613862823970622126945808954842683496637377151180225469409261800869161467402364879561554585345399947589618235872378329510108345004513054262809629917083343715270605155751457391599728436117833
h = 115812446451372389307840774747986196103012628652193338630796109042038320397499948364970459686079508388755154855414919871257982157430015224489195284512204803276307238226421244647463550637321174259849701618681565567468929295822889537962306471780258801529979716298619553323655541002084406217484482271693997457806
p_0 = 4055618

p_approx = p_0 << 490
x_approx = 2021 * p_approx + 1120 * (N // p_approx)

P.<x_diff> = PolynomialRing(Zmod(N))
f = (x_approx + x_diff)^2 + 1 - h * (x_approx + x_diff)

res = f.small_roots(X = 2^500, epsilon = 0.02)
x_diff = Integer(res[0])

x = x_approx + x_diff
assert (h == (inverse_mod(x, N) + x) % N)

p = var('p')
q = var('q')
res = solve([x == 2021 * p + 1120 * q, N == p * q], p, q)

p = Integer(res[0][0].rhs())
q = Integer(res[0][1].rhs())
assert (p * q == N)

d = inverse_mod(65537, (p - 1) * (q - 1))
pt = pow(ct, d, N)

FLAG = long_to_bytes(pt)
print(FLAG)

# n1ctf{093fd4c4-5cc9-427e-98ef-5a04914c8b4e}