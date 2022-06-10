#!/usr/bin/env python3

# https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm

from Crypto.Util.number import long_to_bytes
from math import gcd

def lag(k, a, n):
    s, t = 2, a
    if k == 0:
        return 2
    r = 0
    while k % 2 == 0:
        r += 1
        k //= 2
    B = bin(k)[2:]
    for b in B:
        if b == '0':
            t = (s * t - a) % n
            s = (s **2 - 2) % n
        else:
            s = (s * t - a) % n
            t = (t** 2 - 2) % n
    for _ in range(r):
        s = (s ** 2 - 2) % n
    return s

e = 65537
a = 192948041792305023195893277034532781336
n = 772559547290160010920412621051392165317498598296084946084386444091060134053985973087541256301003639549317798291916637210182966424107689011211268907278162096553174971554689109947325734336069313105789282878112740205249104820920364881
y = 754843853942922590978288450377461057162899072980081889481597335367906588582097339709346991452615504422434823707721197330881973700388055679080814559570248350531810374624494389646277873934234170885190847719684200687267925979436889772
C = (9083709539234699681499154559006541145975405183323215645582033885264296926186620280958201308661746194284022873377667665062501349047202357817146222033735539058147945671541486202387767382626733526030628929826676457655813734637020574, 625771268848498566477216756364333384750869252753726246816617776940622341574266652518894117167008714362418009723919180248010211052475114496172513936468417590330695688907796560242492250071433491517329459840410014214097477377322316145)

'''
from tqdm import tqdm
from gmpy2 import iroot
from Crypto.Util.number import inverse

n = 772559547290160010920412621051392165317498598296084946084386444091060134053985973087541256301003639549317798291916637210182966424107689011211268907278162096553174971554689109947325734336069313105789282878112740205249104820920364881
q_upper = int(iroot(n, 6)[0])

for i in tqdm(range(2**32)):
    q = q_upper + i
    if n % q == 0:
        break

p = n // q
d = inverse(65537, (p**2 - 1) * (q**2 - 1))
print(d)

# 538062293807748210425073365436378141893890370157686998223999073641973059143858547185432307560123604450541751452708821753054649593921861588374616199120801510769028094278418259821111969267405342068727427121195273649389491282836703625608576864378084568410068552968112511647386960827658441215595425435453081627394766022422271443374281541657618699527389499082843376820586363199973252939301589961866277146918490844609051234717197542299805844879307298569219975706345473
'''

d = 538062293807748210425073365436378141893890370157686998223999073641973059143858547185432307560123604450541751452708821753054649593921861588374616199120801510769028094278418259821111969267405342068727427121195273649389491282836703625608576864378084568410068552968112511647386960827658441215595425435453081627394766022422271443374281541657618699527389499082843376820586363199973252939301589961866277146918490844609051234717197542299805844879307298569219975706345473

x = pow(d, e, n)

ct = C[1] - lag(x, C[0], n)

FLAG = lag(d, ct, n)

print(long_to_bytes(FLAG))

# ASIS{N0w_LUc4s_vers10n_Of_the_El_Gamal_3nCryp7iOn_5cH3mE_:P}
