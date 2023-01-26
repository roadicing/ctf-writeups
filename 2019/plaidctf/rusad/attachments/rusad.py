#!/usr/bin/env python3

import argparse
import secrets
import random
import hashlib
import sys
import pickle

from copy import deepcopy


class Key:
	PRIVATE_INFO = ['P', 'Q', 'D', 'DmP1', 'DmQ1']
	def __init__(self, **kwargs):
		for k, v in kwargs.items():
			setattr(self, k, v)
		assert self.bits % 8 == 0

	def ispub(self):
		return all(not hasattr(self, key) for key in self.PRIVATE_INFO)

	def ispriv(self):
		return all(hasattr(self, key) for key in self.PRIVATE_INFO)

	def pub(self):
		p = deepcopy(self)
		for key in self.PRIVATE_INFO:
			if hasattr(p, key):
				delattr(p, key)
		return p

	def priv(self):
		raise NotImplementedError()


def genprime(bits):
	while True:
		p = secrets.randbits(bits-1) | (1 << (bits-1))
		if isprime(p): return p

def isprime(n):
	return n > 1 and miller_rabin(n)

def miller_rabin(n, rounds=50):
	assert n > 1
	if not (n & 1): return n == 2
	if n < 15: return n != 9
	d, r = n-1, 0
	while not (d & 1):
		d >>= 1
		r += 1
	assert (d & 1) == 1 and d << r == n-1
	for _ in range(rounds):	
		x = pow(random.randrange(2, n-1), d, n)
		if x == 1 or x == n-1: continue
		for i in range(1, r):
			x = x * x % n
			if x == n-1: break
		else:
			return False
	return True

def egcd(a1, a2):
	x1, x2 = 1, 0
	y1, y2 = 0, 1
	while a2:
		q = a1 // a2
		a1, a2 = a2, a1 - q * a2
		x1, x2 = x2, x1 - q * x2
		y1, y2 = y2, y1 - q * y2
	return (x1, y1, a1)

def genkey(bits):
	assert bits % 2 == 0
	while True:
		p = genprime(bits // 2)
		q = genprime(bits // 2)
		e = 65537
		d, _, g = egcd(e, (p-1) * (q-1))
		if g != 1: continue
		iQmP, iPmQ, _ = egcd(q, p)
		return Key(
			N=p*q, P=p, Q=q, E=e, D=d%((p-1)*(q-1)), DmP1=d%(p-1), DmQ1=d%(q-1),
			iQmP=iQmP%p, iPmQ=iPmQ%q, bits=bits,
		)


def bytes2num(data):
	return sum(x << (8 * i) for i, x in enumerate(data))

def num2bytes(data, size):
	assert 0 <= data and (data >> (size * 8)) == 0
	return bytes(data >> (8 * i) & 0xff for i in range(size))

def xor(d1, d2):
	return bytes(
		d1[i % len(d1)] ^ d2[i % len(d2)]
		for i in range(max(len(d1), len(d2)))
	)


def random_oracle(source, length, hash=hashlib.sha256):
	return b''.join(
		hash(source + num2bytes(idx, 4)).digest()
		for idx in range((length - 1) // hash().digest_size + 1)
	)[:length]

def pad(data, bits, hash=hashlib.sha256):
	k = hash().digest_size
	Xlen = (bits - 1) // 8 - k
	assert len(data) + k <= Xlen
	X = data.ljust(Xlen, b'\x00')
	Y = num2bytes(secrets.randbits(k * 8), k)
	X = xor(X, random_oracle(Y, Xlen, hash))
	Y = xor(Y, random_oracle(X, k, hash))
	return X + Y + b'\x00'

def unpad(data, hash=hashlib.sha256):
	if data[-1] != 0: return None
	data = data[:-1]

	k = hash().digest_size
	Xlen = len(data) - k
	X, Y = data[:Xlen], data[-k:]
	Y = xor(Y, random_oracle(X, k, hash))
	X = xor(X, random_oracle(Y, Xlen, hash))
	if all(b == 0 for b in X[-k:]):
		return X[:-k]
	return None


def encrypt(key, data):
	data = bytes2num(pad(data, key.bits))
	assert 0 <= data and data < key.N
	data = pow(data, key.E, key.N)
	return num2bytes(data, key.bits // 8)

def decrypt(key, data):
	assert key.ispriv() and len(data) * 8 == key.bits
	data = bytes2num(data)
	assert 0 <= data and data < key.N
	v1 = pow(data, key.DmP1, key.P)
	v2 = pow(data, key.DmQ1, key.Q)
	data = (v2 * key.P * key.iPmQ + v1 * key.Q * key.iQmP) % key.N
	return unpad(num2bytes(data, key.bits // 8))


def action_decrypt(args):
	data = args.i.read()
	data = decrypt(args.k, data)
	if data is None:
		print('Failed to decrypt', file=sys.stderr)
		exit(1)
	args.o.write(data)

def action_encrypt(args):
	data = args.i.read()
	data = encrypt(args.k, data)
	args.o.write(data)

def action_keygen(args):
	key = genkey(args.bits)
	pickle.dump(key, args.priv)
	pickle.dump(key.pub(), args.pub)


def keysize(string):
	try:
		value = int(string)
	except ValueError:
		raise argparse.ArgumentTypeError(f'{string:r} is not a number')
	if value % 8:
		raise argparse.ArgumentTypeError(f'{value} must be a multiple of 8')
	if 256 <= value and value < 8192:
		return value
	raise argparse.ArgumentTypeError(f'{value} out of range')

def keyfile(private=False):
	def func(string):
		f = argparse.FileType('rb')(string)
		key = pickle.load(f)
		if not isinstance(key, Key):
			raise argparse.ArgumentTypeError(f'{string:r} did not specify a valid key')
		if private and not key.ispriv():
			raise argparse.ArgumentTypeError(f'{string:r} did not specify a private key')
		return key
	return func


def main():
	main = argparse.ArgumentParser(description='The new age of RSA is upon us.')
	main.set_defaults(func=None)
	subs = main.add_subparsers(help='action to perform')

	p = subs.add_parser('keygen', help='generate a new RSA key')
	p.set_defaults(func=action_keygen)
	p.add_argument('--bits', type=keysize, help='number of bits in the generated key', default=4096)
	p.add_argument('--priv', type=argparse.FileType('wb'), metavar='KEY', help='where to store the private key', required=True)
	p.add_argument('--pub', type=argparse.FileType('wb'), metavar='KEY', help='where to store the public key', required=True)

	p = subs.add_parser('encrypt', help='encrypt your secrets')
	p.set_defaults(func=action_encrypt)
	p.add_argument('-i', type=argparse.FileType('rb'), metavar='FILE', default=sys.stdin.buffer, help='file to encrypt')
	p.add_argument('-o', type=argparse.FileType('wb'), metavar='FILE', default=sys.stdout.buffer, help='encrypted output')
	p.add_argument('-k', type=keyfile(), metavar='KEY', help='key to use', required=True)

	p = subs.add_parser('decrypt', help='decrypt your secrets')
	p.set_defaults(func=action_decrypt)
	p.add_argument('-i', type=argparse.FileType('rb'), metavar='FILE', default=sys.stdin.buffer, help='file to decrypt')
	p.add_argument('-o', type=argparse.FileType('wb'), metavar='FILE', default=sys.stdout.buffer, help='decrypted output')
	p.add_argument('-k', type=keyfile(private=True), metavar='KEY', help='key to use', required=True)

	args = main.parse_args()
	if not args.func:
		main.print_help()
		exit(1)
	args.func(args)

if __name__ == '__main__': main()