#!/usr/bin/env python3

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def recover_keystream(key, public):
    st = set(key)
    keystream = []
    for v0, v1 in public:
        if v0 in st:
            keystream.append(0)
        elif v1 in st:
            keystream.append(1)
        else:
            assert False, "Failed to recover the keystream"
    return keystream

def bytes_to_bits(inp):
    res = []
    for v in inp:
        res.extend(list(map(int, format(v, '08b'))))
    return res

def bits_to_bytes(inp):
    res = []
    for i in range(0, len(inp), 8):
        res.append(int(''.join(map(str, inp[i:i+8])), 2))
    return bytes(res)

# https://stackoverflow.com/questions/56856378/fast-computation-of-matrix-rank-over-gf2
def gf2_rank(l):
    rows = l.copy()
    rank = 0
    while rows:
        pivot_row = rows.pop()
        if pivot_row:
            rank += 1
            lsb = pivot_row & -pivot_row
            for index, row in enumerate(rows):
                if row & lsb:
                    rows[index] = row ^ pivot_row
    return rank

def check(A, r):
    return gf2_rank(A + [r]) < len(A) + 1

f = open("output.txt", "r")

enc = bytes_to_bits(bytes.fromhex(f.readline().strip()))
public = eval(f.readline().strip())

key = []
unknown_key = []
for k, f in public:
    if 0 in (k, f):
        key.append(k + f)
    else:
        unknown_key.append([k, f])

while len(unknown_key):
    for k, f in unknown_key:
        if check(key, k):
            key.append(f)
        elif check(key, f):
            key.append(k)
        else:
            continue
        unknown_key.remove([k, f])
    print(len(unknown_key))

keystream = recover_keystream(key, public)

FLAG = bits_to_bytes(xor(enc, keystream))
print(FLAG)

# pbctf{I_hope_you_enjoyed_this_challenge_now_how_about_playing_Metroid_Dread?}
