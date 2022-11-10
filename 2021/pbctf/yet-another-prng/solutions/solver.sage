#!/usr/bin/env sage

import random
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.modules.free_module_integer import IntegerLattice

class seed_PRNG:
    def __init__(self, seed):
        self.m1 = 2 ** 32 - 107
        self.m2 = 2 ** 32 - 5
        self.m3 = 2 ** 32 - 209
        self.M = 2 ** 64 - 59
        rnd = random.Random(b'rbtree')
        self.a1 = [rnd.getrandbits(20) for _ in range(3)]
        self.a2 = [rnd.getrandbits(20) for _ in range(3)]
        self.a3 = [rnd.getrandbits(20) for _ in range(3)]
        self.x = seed[:3]
        self.y = seed[3:6]
        self.z = seed[6:]
    def out(self):
        o = (2 * self.m1 * self.x[0] - self.m3 * self.y[0] - self.m2 * self.z[0]) % self.M
        self.x = self.x[1:] + [sum(x * y for x, y in zip(self.x, self.a1)) % self.m1]
        self.y = self.y[1:] + [sum(x * y for x, y in zip(self.y, self.a2)) % self.m2]
        self.z = self.z[1:] + [sum(x * y for x, y in zip(self.z, self.a3)) % self.m3]
        return int(o).to_bytes(8, byteorder='big')

class var_PRNG:
    def __init__(self, x_list, y_list, z_list, gx_list, gy_list, gz_list, k_list):
        self.m1 = 2 ** 32 - 107
        self.m2 = 2 ** 32 - 5
        self.m3 = 2 ** 32 - 209
        self.M = 2 ** 64 - 59
        rnd = random.Random(b'rbtree')
        self.a1 = [rnd.getrandbits(20) for _ in range(3)]
        self.a2 = [rnd.getrandbits(20) for _ in range(3)]
        self.a3 = [rnd.getrandbits(20) for _ in range(3)]
        self.x = x_list
        self.y = y_list
        self.z = z_list
        self.gx = gx_list + [0] * 3
        self.gy = gy_list + [0] * 3
        self.gz = gz_list + [0] * 3
        self.k = k_list
        self.cnt = 0
    def out(self):
        o = (2 * self.m1 * self.x[0] - self.m3 * self.y[0] - self.m2 * self.z[0]) - self.k[self.cnt] * self.M
        self.x = self.x[1:] + [sum(x * y for x, y in zip(self.x, self.a1)) - self.gx[self.cnt] * self.m1]
        self.y = self.y[1:] + [sum(x * y for x, y in zip(self.y, self.a2)) - self.gy[self.cnt] * self.m2]
        self.z = self.z[1:] + [sum(x * y for x, y in zip(self.z, self.a3)) - self.gz[self.cnt] * self.m3]
        self.cnt += 1
        return o

# https://github.com/rkm0959/Inequality_Solving_with_CVP/blob/main/solver.sage
load("solver.sage")

f =  open("output.txt", "r")

stream = bytes.fromhex(f.readline().strip())
stream = [bytes_to_long(stream[i : i + 8]) for i in range(0, len(stream), 8)]
ct = bytes.fromhex(f.readline().strip())

var_str = ",".join(f"x_{i}" for i in range(3))
var_str += "," + ",".join(f"y_{i}" for i in range(3))
var_str += "," + ",".join(f"z_{i}" for i in range(3))
var_str += "," + ",".join(f"gx_{i}" for i in range(9))
var_str += "," + ",".join(f"gy_{i}" for i in range(9))
var_str += "," + ",".join(f"gz_{i}" for i in range(9))
var_str += "," + ",".join(f"k_{i}" for i in range(12))

P = PolynomialRing(ZZ, var_str)
var_list = list(P.gens())

x_list = var_list[:3]
y_list = var_list[3:6]
z_list = var_list[6:9]
gx_list = var_list[9:18]
gy_list = var_list[18:27]
gz_list = var_list[27:36]
k_list = var_list[36:]

vrng = var_PRNG(x_list, y_list, z_list, gx_list, gy_list, gz_list, k_list)
res = [vrng.out() for _ in range(12)]

B, _ = Sequence(res).coefficient_matrix()
padding = block_matrix(
	[
		[matrix.identity(24), matrix(24, 12)], 
		[matrix(12, 24), matrix(12, 12)], 
		[matrix(12, 24), matrix.identity(12)]
	]
)
M = B.dense_matrix().T.augment(padding)

lb = stream + [0] * 9 + [0] * 15 + [-5] * 12
ub = stream + [2^32] * 9 + [2^20] * 15 + [5] * 12

result, applied_weights, fin = solve(M, lb, ub) 
seed = list(M.solve_left(result)[:9])

srng = seed_PRNG(seed)

_ = [srng.out() for _ in range(12)]

keystream = b''.join([srng.out() for _ in range(len(ct) // 8)])
FLAG = bytes([x ^^ y for x, y in zip(keystream, ct)])
print(FLAG)

# pbctf{Wow_how_did_you_solve_this?_I_thought_this_is_super_secure._Thank_you_for_solving_this!!!}
