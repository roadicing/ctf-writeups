#!/usr/bin/env python3

from tqdm import tqdm
from Crypto.Util.number import *

def decrypt(enc, s, p):
    dic = {}
    dic[0] = enc[0]
    idx_list = [pow(s, i, p) for i in range(p - 1)]
    for i, idx in enumerate(idx_list):
        dic[idx] = enc[i + 1]
    dic_item = sorted(dic.items())
    ans = ''
    for _, c in dic_item:
        ans += c
    return ans

f = open("output.txt", "r")
enc = f.read()[6:]

p = len(enc)
assert isPrime(p)

for s in tqdm(range(p)):
    ans = decrypt(enc, s, p)[:100]
    if ans.startswith("ASIS{"):
        print(ans)

# ASIS{_how_d3CrYpt_Th1S_h0m3_m4dE_anD_wEird_CrYp70_5yST3M?!!!!!!}