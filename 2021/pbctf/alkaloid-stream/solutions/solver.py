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

f = open("output.txt", "r")

enc = bytes_to_bits(bytes.fromhex(f.readline().strip()))
public = eval(f.readline().strip())

ln = len(public)

key = []
v = 0
cnt = 0
pub = public.copy()

for _ in range(ln):
    for k, f in pub:
        if v in (k, f):
            if v == k:
                key.append(f)
                break
            else:
                key.append(k)
                break
    pub.remove([k, f])
    v ^= key[-1]
    if len(key) > (ln // 3):
        v ^= key[cnt]
        cnt += 1

keystream = recover_keystream(key, public)

FLAG = bits_to_bytes(xor(enc, keystream))
print(FLAG)

# pbctf{super_duper_easy_brute_forcing_actually_this_one_was_made_by_mistake}