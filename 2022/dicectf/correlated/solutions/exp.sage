#!/usr/bin/env sage

import time
from pwn import *
from tqdm import tqdm

taps = [45, 40, 39, 36, 35, 34, 33, 32, 30, 28, 27, 23, 22, 21, 19, 17, 16, 15, 14, 13, 9, 7, 3, 0]
n = 48
m = 20000

class LFSR:
    def __init__(self, key, taps):
        self._s = key
        self._t = taps            

    def _sum(self, L):
        s = 0
        for x in L:
            s ^^= x
        return s

    def _clock(self):
        b = self._s[0]
        self._s = self._s[1:] + [self._sum(self._s[p] for p in self._t)]
        return b

    def bit(self):
        return self._clock()

IP = b"mc.ax"
PORT = 31683

M = matrix(GF(2), n - 1, 1)
M = M.augment(identity_matrix(GF(2), n - 1))
v = vector(GF(2), n)
for i in taps:
    v[i] = 1

M = M.stack(v)

outputs = [[1] + [0] * (n - 1)]
Q = identity_matrix(GF(2), n)
for i in range(m):
    Q *= M
    outputs.append(Q[0])

O = matrix(GF(2), outputs)

token = False
check_length = 100

while True:
    if token == True:
        break

    st_time = int(time.time())

    io = remote(IP, PORT)
    io.recvuntil(b"80.0% accuracy\n")

    stream_0 = list(map(int, bin(int(io.recvline().strip()))[2:].zfill(m)))

    for _ in tqdm(range(50000)):
        if int(time.time()) - st_time > 60:
            break

        rnd_idx = random.sample(range(n, m), n)

        A = O[rnd_idx]
        b = vector(GF(2), [stream_0[idx] for idx in rnd_idx])
        try:
            res = A.solve_right(b)
        except:
            continue

        lfsr = LFSR(list(map(int, res)), taps)
        stream_1 = [int(lfsr.bit()) for _ in range(check_length)]

        stream_diff = [i ^^ j for i, j in zip(stream_0[:check_length], stream_1)]
        if stream_diff.count(0) > 0.8 * check_length:
            token = True
            break

key = int(''.join(list(map(str, res)))[::-1], 2)
io.sendlineafter(b"what is my key?", str(key).encode())

io.interactive()

# dice{low-flavor-solar-radiation-efec606520fba4c}
