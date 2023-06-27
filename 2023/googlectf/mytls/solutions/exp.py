#!/usr/bin/env python3

import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib
import os
from secrets import token_hex

import string
from pwn import *
from tqdm import tqdm

DIC = string.ascii_letters + string.digits + "+/=" + "-\n"

IP = "mytls.2023.ctfcompetition.com"
PORT = 1337

def encrypt(message, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
    encryptor = cipher.encryptor()
    message = message.encode('utf-8')
    payload = encryptor.update(message + b'\x00' * (16 - len(message) % 16)) + encryptor.finalize()
    return binascii.hexlify(payload).decode('utf-8')

def decrypt(payload, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(binascii.unhexlify(iv)))
    decryptor = cipher.decryptor()
    payload = binascii.unhexlify(payload)
    res = decryptor.update(payload)
    return res.strip(b'\x00')

def get_hash(io, msg):
    _ = io.recvline() # Select the storage slot [0-9]:
    io.sendline(encrypt("../../app/server-ecdhkey.pem", server_ephemeral_random, derived_key))
    _ = io.recvline() # Gimme your secrets:
    payload = encrypt(msg, server_ephemeral_random, derived_key)
    _ = io.sendline(payload)
    res = io.recvline().strip() # Saved! Previous secret reference: 
    target_hash = decrypt(res, server_ephemeral_random, derived_key).decode().replace("Saved! Previous secret reference: ", "")
    return target_hash

client_cert_content = open("guest-ecdhcert.pem", "r").read()

server_cert_content = open('server-ecdhcert.pem', 'r').read()
server_cert = x509.load_pem_x509_certificate(server_cert_content.encode('utf-8'))
server_public_key = server_cert.public_key()

client_ephemeral_key_content = open("guest-ecdhkey.pem", "r").read()
client_ephemeral_key = serialization.load_pem_private_key(client_ephemeral_key_content.encode('utf-8'), password = None)

client_ephemeral_public_key = client_ephemeral_key.public_key()
client_ephemeral_public_key_content = client_ephemeral_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

io = remote(IP, PORT)

io.sendlineafter("Please provide the client certificate in PEM format:\n", client_cert_content)

client_ephemeral_random = 'A' * 32
io.sendlineafter("Please provide the ephemeral client random:\n", client_ephemeral_random)

io.sendlineafter("Please provide the ephemeral client key:\n", client_ephemeral_public_key_content)

io.recvuntil("Server ephemeral random:\n")
server_ephemeral_random = io.recvline().strip().decode()

io.recvuntil("Server ephemeral key:\n")
server_ephemeral_public_key_content = ''
for _ in range(4):
    server_ephemeral_public_key_content += io.recvline().decode()

server_ephemeral_public_key = serialization.load_pem_public_key(server_ephemeral_public_key_content.encode('utf-8'))

server_ephemeral_secret = client_ephemeral_key.exchange(ec.ECDH(), server_ephemeral_public_key)
server_secret = client_ephemeral_key.exchange(ec.ECDH(), server_public_key)
derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'SaltyMcSaltFace', info=b'mytls').derive(server_ephemeral_secret + server_secret + client_ephemeral_random.encode('utf-8') + server_ephemeral_random.encode('utf-8'))

client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
client_hmac.update(b'client myTLS successful!')
client_hmac_content = client_hmac.finalize().hex()
io.sendlineafter("Please provide the client HMAC:\n", client_hmac_content)

io.recvline() # Server HMAC:
io.recvline() # Server HMAC hex
io.recvline() # message

'''
target_hash = get_hash(io, '')

server_key_content = ''
for i in range(241):
    for j in tqdm(dic):
        msg = server_key_content + j
        _ = get_hash(io, msg)
        if get_hash(io, msg) == target_hash:
            server_key_content += j
            break

print(server_key_content)

-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgodXSjxjUm89w/y6m
hRc9c7aOOYIgy5m4K++AXeErUKahRANCAARNWVuTXe/JBFanevD4MMlIDyZ8xXKz
nyUf63kGe9RBfFPek03cHJhEM5Fhe/1hHS2Jz2+R9zZWHd5gVYWFf2uC
-----END PRIVATE KEY-----
'''

server_key_content = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgodXSjxjUm89w/y6m
hRc9c7aOOYIgy5m4K++AXeErUKahRANCAARNWVuTXe/JBFanevD4MMlIDyZ8xXKz
nyUf63kGe9RBfFPek03cHJhEM5Fhe/1hHS2Jz2+R9zZWHd5gVYWFf2uC
-----END PRIVATE KEY-----'''
server_key = serialization.load_pem_private_key(server_key_content.encode('utf-8'), password = None)

admin_cert_content = open("admin-ecdhcert.pem", "r").read()
admin_cert = x509.load_pem_x509_certificate(admin_cert_content.encode('utf-8'))

admin_public_key = admin_cert.public_key()
admin_public_key_content = admin_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

io.close()
io = remote(IP, PORT)

io.sendlineafter("Please provide the client certificate in PEM format:\n", admin_cert_content)

client_ephemeral_random = 'A' * 32
io.sendlineafter("Please provide the ephemeral client random:\n", client_ephemeral_random)

io.sendlineafter("Please provide the ephemeral client key:\n", client_ephemeral_public_key_content)

io.recvuntil("Server ephemeral random:\n")
server_ephemeral_random = io.recvline().strip().decode()

io.recvuntil("Server ephemeral key:\n")
server_ephemeral_public_key_content = ''
for _ in range(4):
    server_ephemeral_public_key_content += io.recvline().decode()

server_ephemeral_public_key = serialization.load_pem_public_key(server_ephemeral_public_key_content.encode('utf-8'))

server_ephemeral_secret = client_ephemeral_key.exchange(ec.ECDH(), server_ephemeral_public_key)
server_secret = server_key.exchange(ec.ECDH(), admin_public_key)
derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'SaltyMcSaltFace', info=b'mytls').derive(server_ephemeral_secret + server_secret + client_ephemeral_random.encode('utf-8') + server_ephemeral_random.encode('utf-8'))

client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
client_hmac.update(b'client myTLS successful!')
client_hmac_content = client_hmac.finalize().hex()
io.sendlineafter("Please provide the client HMAC:\n", client_hmac_content)

io.recvline() # Server HMAC:
io.recvline() # Server HMAC hex
ct = io.recvline().strip() # message

FLAG = decrypt(ct, server_ephemeral_random, derived_key).decode()
print(FLAG) # CTF{KeyC0mpromiseAll0w51mpersonation}