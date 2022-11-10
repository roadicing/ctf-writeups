#!/usr/bin/env sage

from Crypto.Util.number import long_to_bytes

e = 65537
n = 0x1ffc7dc6b9667b0dcd00d6ae92fb34ed0f3d84285364c73fbf6a572c9081931be0b0610464152de7e0468ca7452c738611656f1f9217a944e64ca2b3a89d889ffc06e6503cfec3ccb491e9b6176ec468687bf4763c6591f89e750bf1e4f9d6855752c19de4289d1a7cea33b077bdcda3c84f6f3762dc9d96d2853f94cc688b3c9d8e67386a147524a2b23b1092f0be1aa286f2aa13aafba62604435acbaa79f4e53dea93ae8a22655287f4d2fa95269877991c57da6fdeeb3d46270cd69b6bfa537bfd14c926cf39b94d0f06228313d21ec6be2311f526e6515069dbb1b06fe3cf1f62c0962da2bc98fa4808c201e4efe7a252f9f823e710d6ad2fb974949751
ct = 0x60160bfed79384048d0d46b807322e65c037fa90fac9fd08b512a3931b6dca2a745443a9b90de2fa47aaf8a250287e34563e6b1a6761dc0ccb99cb9d67ae1c9f49699651eafb71a74b097fc0def77cf287010f1e7bd614dccfb411cdccbb84c60830e515c05481769bd95e656d839337d430db66abcd3a869c6348616b78d06eb903f8abd121c851696bd4cb2a1a40a07eea17c4e33c6a1beafb79d881d595472ab6ce3c61d6d62c4ef6fa8903149435c844a3fab9286d212da72b2548f087e37105f4657d5a946afd12b1822ceb99c3b407bb40e21163c1466d116d67c16a2a3a79e5cc9d1f6a1054d6be6731e3cd19abbd9e9b23309f87bfe51a822410a62

P.<x> = PolynomialRing(ZZ)

for y in range(10000):
    q = (((1 << 1024) - 1) - x) + y # p + q == ((1 << 1024) - 1) + y
    f = x * q - n
    res = f.roots()
    if res != []:
        t = Integer(res[0][0])
        if n % t == 0 and is_prime(t):
            p = t
            break

q = n // p
phi = (p - 1) * (q - 1)

d = inverse_mod(e, phi)
pt = power_mod(ct, d, n)

FLAG = long_to_bytes(pt)
print(FLAG)

# zer0pts{F3rm4t,y0ur_m3th0d_n0_l0ng3r_w0rks.y0u_4r3_f1r3d}