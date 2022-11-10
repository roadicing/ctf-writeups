#!/usr/bin/env sage

# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

import json
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

IP = b"good-hash.chal.perfect.blue"
PORT = 1337

key = b'goodhashGOODHASH'
ACCEPTABLE = string.ascii_letters + string.digits + string.punctuation + " "

F.<x> = GF(2^128, name = 'x', modulus = x^128 + x^7 + x^2 + x + 1)

def int_to_element(x):
    return F.fetch_int(int(bin(x)[2:].zfill(128)[::-1], 2))

def element_to_int(x):
    return int(bin(x.integer_representation())[2:].zfill(128)[::-1], 2)

def pad(m, block_size):
    return m + b'\x00'* ((block_size - len(m) % block_size) % block_size)

io = remote(IP, PORT)

_ = io.recvuntil(b"Body: ")
token = pad(io.recvline().strip(), 16)

_ = io.recvuntil(b"Hash: ")
target_hash = io.recvline().strip()

cipher = AES.new(key, AES.MODE_ECB)
H = bytes_to_long(cipher.encrypt(b'\x00' * 16))

token_list = [None]
for i in range(0, len(token), 16):
    token_list.append(token[i: i + 16])

token_hash = [0]
for i in range(1, len(token_list)):
    token_hash.append(element_to_int(int_to_element(token_hash[-1] ^^ bytes_to_long(token_list[i])) * int_to_element(H)))

payload_list = [None, b'{"admin":true, "', None, None, token[48:]]

payload_hash = [0] * 5
payload_hash[1] = element_to_int(int_to_element(payload_hash[0] ^^ bytes_to_long(payload_list[1])) * int_to_element(H))

while True:
    payload_list[2] = ''.join([random.choice(ACCEPTABLE) for _ in range(16)]).encode()
    payload_hash[2] = element_to_int(int_to_element(payload_hash[1] ^^ bytes_to_long(payload_list[2])) * int_to_element(H))
    payload_list[3] = long_to_bytes(element_to_int(int_to_element(token_hash[3]) * int_to_element(H)^(-1)) ^^ payload_hash[2])
    try:
        if all([i in ACCEPTABLE for i in payload_list[3].decode()]):
            print(b"Found")
            print(payload_list[3])
            break
    except:
        continue

payload = b''.join(payload_list[1:]).replace(b"\x00", b'')
io.sendlineafter(b'> ', payload)

io.interactive()

# pbctf{GHASH_is_short_for_GoodHash_:joy:}
