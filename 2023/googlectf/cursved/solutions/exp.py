#!/usr/bin/env python3

from pwn import *

IP = "cursved.2023.ctfcompetition.com"
PORT = 1337

from hashlib import sha256
from os import urandom

def bytes_to_hexstr(buf):
    return "".join(["{0:02X}".format(b) for b in buf])

def bytes_to_int(buf):
    return int(bytes_to_hexstr(buf), 16)

def random_int(n):
    return bytes_to_int(urandom(n))

def sha256_as_int(x):
    return int(sha256(x).hexdigest(), 16)

def check_type(x, types):
    if len(x) != len(types):
        return False
    for a,b in zip(x, types):
        if not isinstance(a, b):
            return False
    return True

class Curve:
    def __init__(self, p, D, n):
        self.p = p
        self.D = D
        self.n = n
    def __repr__(self):
        return f"Curve(0x{self.p:X}, 0x{self.D:X})"
    def __eq__(self, other):
        return self.p == other.p and self.D == other.D
    def __matmul__(self, other):
        assert(check_type(other, (int, int)))
        assert(other[0]**2 % self.p == (self.D*other[1]**2 + 1) % self.p)
        return Point(self, *other)

class Point:
    def __init__(self, C, x, y):
        assert(isinstance(C, Curve))
        self.C = C
        self.x = x
        self.y = y
    def __repr__(self):
        return f"(0x{self.x:X}, 0x{self.y:X})"
    def __eq__(self, other):
        assert(self.C == other.C)
        return self.x == other.x and self.y == other.y
    def __add__(self, other):
        assert(self.C == other.C)
        x0, y0 = self.x, self.y
        x1, y1 = other.x, other.y
        return Point(self.C, (x0*x1 + self.C.D*y0*y1) % self.C.p, (x0*y1 + x1*y0) % self.C.p)
    def __rmul__(self, n):
        assert(check_type((n,), (int,)))
        P = self.C @ (1, 0)
        Q = self
        while n:
            if n & 1:
                P = P + Q
            Q = Q + Q
            n >>= 1
        return P
    def to_bytes(self):
        l = len(hex(self.C.p)[2:])
        return self.x.to_bytes(l, "big") + self.y.to_bytes(l, "big")

class Priv:
    def __init__(self, k, G):
        self.k = k
        self.G = G
        self.P = k*G
    def get_pub(self):
        return Pub(self.G, self.P)
    def sign(self, m):
        r = random_int(16) % self.G.C.n
        R = r*self.G
        e = sha256_as_int(R.to_bytes() + self.P.to_bytes() + m) % self.G.C.n
        return (R, (r + self.k*e) % self.G.C.n)

p = 0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B3
q = (p - 1) // 2
D = 3

io = remote(IP, PORT)

io.recvuntil("pub = ")
P = eval(io.recvline())

s = pow(3, (p + 1) // 4, p)
G = (2, 1)

g = (G[0] - s * G[1]) % p
y = (P[0] - s * P[1]) % p

'''
print(g) # 12527757556323992250036778502891051249984474232171227560335608894171352453586
print(y) # 2603551142613802156596017541251324868039611736645656770096264806834683812589
print(p) # 23536927400084672584547780360605321978508195328072019467170066018450918216627
print(q) # 11768463700042336292273890180302660989254097664036009733585033009225459108313

./cado-nfs.py -dlp -ell 11768463700042336292273890180302660989254097664036009733585033009225459108313 target=12527757556323992250036778502891051249984474232171227560335608894171352453586 23536927400084672584547780360605321978508195328072019467170066018450918216627
...
Info:root: If you want to compute one or several new target(s), run ./cado-nfs.py /tmp/cado.xuebapo2/p75.parameters_snapshot.0 target=<target>[,<target>,...]
Info:root: logbase = 9124582963071133528786001226298469992950948841420505614055341832865405446557
Info:root: target = 12527757556323992250036778502891051249984474232171227560335608894171352453586
Info:root: log(target) = 7797185697465868868197802026550217130540658886988752360703529504066867930948 mod ell
7797185697465868868197802026550217130540658886988752360703529504066867930948

./cado-nfs.py /tmp/cado.xuebapo2/p75.parameters_snapshot.0 target=2603551142613802156596017541251324868039611736645656770096264806834683812589
...
Info:root: log(target) = 8883185604700605024234436697645921191164872927743556176990899909133895490469 mod ell
8883185604700605024234436697645921191164872927743556176990899909133895490469

gg = 7797185697465868868197802026550217130540658886988752360703529504066867930948
yy = 8883185604700605024234436697645921191164872927743556176990899909133895490469

private_key = (yy * pow(gg, -1, q)) % q
print(private_key) # 597042838662739992479017662198571932571177156379622917145185173378909836425
'''

private_key = 597042838662739992479017662198571932571177156379622917145185173378909836425

io.recvuntil("nonce = ")
nonce = bytes.fromhex(io.recvline().strip().decode())

C = Curve(p, D, p - 1)
G = C @ (0x2, 0x1)
priv = Priv(private_key, G)

sig = priv.sign(nonce)

ans = f"{sig[0].x} {sig[0].y} {sig[1]}"
io.sendline(ans)

io.interactive() # CTF{pe11_conics_are_not_quite_e11iptic_curves}