#!/usr/bin/env sage

# https://crypto.stackexchange.com/questions/6518/finding-roots-in-mathbbz-p

from Crypto.Util.number import long_to_bytes

N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
ct = 19441066986971115501070184268860318480501957407683654861466353590162062492971

# Using http://factordb.com/
p = 172036442175296373253148927105725488217
q = 337117592532677714973555912658569668821

assert N == p * q

rp_list = Mod(ct, p).nth_root(e, all = True)
rq_list = Mod(ct, q).nth_root(e, all = True)

for rp in rp_list:
    for rq in rq_list:
        pt = crt([int(rp), int(rq)], [p, q])
        FLAG = long_to_bytes(pt)
        if FLAG.startswith(b"dice{"):
            print(FLAG)

# dice{cado-and-sage-say-hello}
