#!/usr/bin/env python3

import time
import json
from pwn import *
from tqdm import tqdm

from client import *

IP = b"43.155.59.224"
PORT = 7777

BLOCK_SIZE = 16

# You need to debug this value according to the delay of communication with the server in your environment.
THRESHOLD = 0.10

# Increase the number of rounds to reduce false positives.
ROUNDS = 10

# Get from `packet.pcapng`
PACKET = {"rsa_data": "391b06a1740b8c9cf1c8d2bb66ba5b191caa8534b4be18c22ce81069658dd2cd3ca3a8d1a3fc8dfab4b68a6b076bf89be807404e0a98dd1bf9daaf8ba34e0556131d3e56cae61c0302d24a177481209e82de7ecf91c2fe66aa39162d7af9c2fdabaf0c444badfc6b82b071fda8e3b26d4d3e57dba25c36298601ae0153c73b7469c472ac4702531c38849772e7c6e24313e6eb7def64a7bec1c21150c1fded52b3ca716d4444b4d75836dff8c92a371f6256ee7a48034f6d5ea949d982f9f05c04d3d7cce10bd11b806cc02088b42fa0cb069390700fb586287ba224ea0b210ebd0479a4f1d2ef5f914bcc861125b7d8d714cf0feecb515c1b1ef869e91ca179", "aes_data": "1709bf9489f6df6dc31491cee4711f7a2a3e050f1ed3e9772442e8a8483e341313713383dd31fbf0133d55e977b8edf54ba832002ee4ee52da32c260b083a35b01626201c36dad6fca7b2be2aa03d90bf5c9a601a24149f55cdcd39f0bf6a032bfabeebee5259a21e188f5c5f8776cd9d7c072054781169174bddbc390e6da21bd7b85f76c93f48914fb1958ac89e464511d9a17fb2174aab825cb13eb3f0dfa"}

def send_data(io, data):
    time_start = time.time()
    io.sendlineafter(b"> ", json.dumps(data))
    _ = io.recvline()
    time_end = time.time()
    return time_end - time_start

def timing_attack(io, data):
    for _ in range(ROUNDS):
        time_diff = send_data(io, data)
        if time_diff > THRESHOLD:
            continue
        else:
            return False
    return True

def oracle(io, ct, mac):
    data = {"rsa_data" : PACKET["rsa_data"], "aes_data" : (ct + mac).hex()}
    return timing_attack(io, data)

def cbc_padding_oracle_attack(io, ct, mac):
    ct_blocks = [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    pt = b''
    for idx in range(1, len(ct_blocks)):
        known_ct_block = b''
        for pad_len in range(1, BLOCK_SIZE + 1):
            for x in tqdm(range(256)):
                new_ct_block = bytes([x]) + known_ct_block
                new_ct_blocks = ct_blocks[:-idx - 1] + [os.urandom(BLOCK_SIZE - pad_len) + new_ct_block] + [ct_blocks[-idx]]
                new_ct = b''.join(new_ct_blocks)
                if oracle(io, new_ct, mac):
                    pt += bytes([pad_len ^ ct_blocks[-idx - 1][-pad_len] ^ x])
                    known_ct_block = bytes([i ^ pad_len ^ (pad_len + 1) for i in new_ct_block])
                    print(pt[::-1])
                    break
    return pt[::-1]

aes_data = bytes.fromhex(PACKET["aes_data"])
ct, mac = aes_data[:-16], aes_data[-16:]

io = remote(IP, PORT)
_ = io.recvline()

# We don't need to recover the whole plaintext, just stop the process when the password is recovered.
pt = cbc_padding_oracle_attack(io, ct, mac)

password = b"R,YR35B7^r@'U3FV"

login(io)

'''
username: admin
password: R,YR35B7^r@'U3FV
admin login ok!

[*] Switching to interactive mode
admin@local> flag
n1ctf{R3m0t3_t1m1ng_4ttack_1s_p0ssibl3__4nd_u_sh0uld_v3r1fy_th3_MAC_f1rs7}
'''