from pwn import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

n = 256
p = 64141017538026690847507665744072764126523219720088055136531450296140542176327

def xor(xs, ys):
    return bytes(x^^y for x, y in zip(xs, ys))

def pad(b, l):
    return b + b"\0" + b"\xff" * (l - (len(b) + 1))

def unpad(b):
    l = -1
    while b[l] != 0:
        l -= 1
    return b[:l]

def from_bytes(b):
    x = int.from_bytes(b[:n // 8], "big")
    y = int.from_bytes(b[n // 8:], "big")
    return (x, y)

IP = b"crypto.ctf.zer0pts.com"
PORT = 10929

while True:
    try:
        io = remote(IP, PORT)

        io.recvuntil(b"sG = ")
        sG = eval(io.recvline())

        tG = (0, 2)
        io.sendlineafter(b"tG = ", str(tG).encode())

        inp = (b"\x00" * 64).hex()
        io.sendline(inp.encode())

        msg = b'\x00' * 31
        send_output = bytes.fromhex(io.recvline().strip().decode())

        share = xor(pad(msg, 64), send_output)
        stG = from_bytes(share)

        s = discrete_log(Mod(stG[1], p), Mod(2, p))

        inp = (b"flag\x00").hex()
        io.sendline(inp.encode())

        send_output = bytes.fromhex(io.recvline().strip().decode())
        ct = unpad(xor(send_output, share))

        aes = AES.new(key=sha256(long_to_bytes(s)).digest(), mode=AES.MODE_ECB)
        FLAG = aes.decrypt(ct)
    except:
        io.close()
        continue

    if FLAG.startswith(b"zer0pts{"):
        print(FLAG)
        break

# zer0pts{edwards_what_the_hell_is_this}