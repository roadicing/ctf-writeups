#!/usr/bin/env python3

from scapy.all import *
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES, ARC4, PKCS1_v1_5
from Crypto.Util.number import bytes_to_long as b2l

def collect_arc4_ct(pcap, client_sport = 50671):
    client_arc4_ct = server_arc4_ct = b''
    for pkt in pcap:
        try:
            if pkt.sport == client_sport:
                client_arc4_ct += pkt.load
            else:
                server_arc4_ct += pkt.load
        except:
            continue
    return client_arc4_ct, server_arc4_ct

def collect_rsa_ct_and_aes_ct(arc4_pt):
    pt = arc4_pt
    dic = {}
    while pt:
        length, type, id = map(b2l, [pt[: 4], pt[4: 8], pt[8: 12]])
        data = pt[12: 12 + (length - 8)]
        if type == 0:
            dic[id] = b''
        elif type == 1:
            dic[id] += data
        pt = pt[4 + length:]
    nums = len(dic)
    rsa_ct_dic = {}; aes_ct_dic = {}
    for i in range(nums):
        data = dic[i]
        rsa_ct = data[2: 2 + 256]
        rsa_ct_dic[i] = rsa_ct
        data = data[2 + 256 + 32: ]
        while data:
            aes_ct_length = b2l(data[: 4])
            aes_ct = data[4: 4 + 16 + aes_ct_length]
            aes_ct_dic[i] = aes_ct
            data = data[4 + 16 + aes_ct_length: ]
    return rsa_ct_dic, aes_ct_dic

def arc4_decrypt(ct, key):
    cipher = ARC4.new(key)
    pt = cipher.decrypt(ct)
    return pt

def rsa_decrypt(ct, sk):
    cipher = PKCS1_v1_5.new(sk)
    pt = cipher.decrypt(ct, sentinel = None)
    return pt

def aes_decrypt(ct, key):
    iv, ct = ct[: 16], ct[16: ]
    cipher = AES.new(key, mode = AES.MODE_CBC, iv = iv)
    pt = cipher.decrypt(ct)
    return pt

pcap = rdpcap('flag2.pcapng')
client_arc4_ct, server_arc4_ct = collect_arc4_ct(pcap)

arc4_key = b'explorer'
client_arc4_pt = arc4_decrypt(client_arc4_ct, arc4_key)
server_arc4_pt = arc4_decrypt(server_arc4_ct, arc4_key)

client_rsa_ct_and_aes_ct = collect_rsa_ct_and_aes_ct(client_arc4_pt)
server_rsa_ct_and_aes_ct = collect_rsa_ct_and_aes_ct(server_arc4_pt)

client_rsa_sk = RSA.import_key("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC93GDINPM6HX2+\nNN3bCznyri2rDHDVcamzA/rPDXi9Mb2hu1Ypqek4km/kf4MKDsrOU/3T5mcdx5kA\n80s7mBWlGaItg/sy6dsh2XOoKVEHcZYyrbSAbkYrT9CoLLM/JlipbsalKenkW9Jl\nHB0h+vwv/rAwXJ9IMSc4RQkvjn/QKuBPhcXfrfaAIKNO0L+iqUL3asFM2CF8DXZX\ny8pLAxMy2PDJLtb0I/rXDWRImWlBcIWBrhg7lDA0UxWXDD1i5MmMlvxmyho1F8Br\nh7ietK3XW7LWshD2ARIDgPoTZ7lZm7P9JbKSN+Uk7fay6LdkJXYszfT89Owmi7tm\nfUQ41fcBAgMBAAECggEAWyGJru+Dg/Sd44t6peY4lVy3fO/GxRz+qHeTjojX2HAk\nppnGHM96q3XWkWYHHu/Ets6n+msQOcIRldwx01QHp6yrJI/CJkkLrq6yjhfu1dTW\nlFK+XhsQQT/ZVq/GBdzBF+qdHLAGnV7ZmUCqVyIipGLqbPw4VC2Ltr2kUBhlDySA\nA+gCnUrPyVi6O9OFcyDepKMy481gZLLijakINejYrsbdCInz2omHq12w/50tuFt1\ns4XMWJN+AW0g1Hx+tTk2jDX1Wqg/htmJhjGqTj02GLJ/CJQjRodEdA7mx3HGwhis\nigeZgHTdPgP1B5Z9NXwUg9Qxln72D4mGhLCGYcw8VQKBgQD6+oltv1i44BO/ROUJ\nkZPTLWeoBrxP2OOli4aOSilLifeGrUQOSUtvcFHOxzy5RrhvX89f3GnklXcGyHXD\n03wg0/hqL0HM1EzNLmWkJW0Ng5WRFFgfcQIKbWBK9SHhAmKzkHtZPq6NwN8MbZUF\nvndxDtcSOdH0/TbMtCMYYs0MswKBgQDBqM7QxWT6qebCU4YOV+5uwnP+hAunsWkv\nVW7pHgiPnZ8ARRZ9iFIqqiVRvKeeyZBEK22eOJNguz6Cqfz2451D/AHA7sXht+1D\n9GCE/ebvUw+lPNQIRKkAgwQ8Dx+R6ikaUGzUKYhmWYJ5xgS9ZALZ+k4+rSjFg9jV\njFjT7xQvewKBgHo9bJI3kE77VKLkO2ndrdI9Wy9LmIyLZtVKj87d8B8Ko7TEz1Dm\nAgfU/QNppvnWqB4W3DokcK8U3VRAbptidiLHG0ccnT/WZ1HIN1kroWHjpQV0kzc9\nI3FQtIXNvyKItuoehPWCwiHovrqe5OZXTnWSdM47uzdH3Vj2o+FMvfJhAoGAQvus\nbTGZd8oEcvqIx7VKVy0TCdmKXnpSs3iNYDxvIZ2XPXSoDst0ACXRuq/SGm4FZE7R\nH4TaFP8u4+sAADVCVB16Tc1IzIXdnz+LkvRvSCAmrTSY8jMtcWvfrxZcCRBBH0Tq\nH4guEZisNIp1YTySb+rP3YXvMEImYdalcsii5rkCgYEAimnWJ5aFN3TDt3h76CL3\nnRQegnzekJBjXZfcrHdExkgNChWjiz+WU/FW/Z87xMxtfIEwwzzIQHxbKZhgzO/U\np2eXdqH59DvauggbiS3h4p9k2kxWTocztarvdftMW0ncmA4yCKiUQEmWD784JCyx\nOupNNfr2rgViWggVBEtJUIg=\n-----END PRIVATE KEY-----")
server_rsa_sk = RSA.import_key("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbfWw2tfpbGVCl\n+zLy7pVH2vDgfiVj3d+ykCZd5+MOFCFgI8z5LKkG8iBv/D1/wAaQTBSUNDF9kIKX\nPvYYC5L2OuWyqD0ulIxn48kA7QENaKywkIm3LIQ1b/1VU+kksDRJJ5i5NgnzhYMB\nyOxvRP75X3tNeVKKr2y9e3XosPEJAmNFe/07VRMGQOkYZmadHjEuJBP4/Hoo6oCy\nslwAXQQlqOLloF8dVB2tdDCCarw8Sx+e+naJAItnaIM8uUZtFqF0V6KBddPgvpS+\nOlsWv/0g28Nvb69CRGXvOUdW1QAxHhfmyZbacccfljJOLVw68wWw36g8bGAEalKp\ngLGY/Ag3AgMBAAECggEADbfJC6JUA12RrM4GYSiIK/WDGITJ0XQMhxx7SWM0zax0\naY3TQb+I0OZRIK6jKVjXEC2xG5InhbGCd/F3cAlJJhqIQKJDMKYYIGYcKfKmHjBs\nmpxt/wTJPo3BR5P2/lQE8I2I/gpilNXDWlk0bb/iL7PIAQ+UGRbdtPoCZIiqh+WA\nqElaJ4LHXgKBXUpozfEtUa383IcwsQdB1BSwMOnJ5YFrplhx6fTgJ6noFB4eLp7h\nSCSR2018r11UAANqWbc7a40TtLpWUmh3AExCeQACI1RloTSCRWYsXrxFMH6ZGDvE\nK+Q9LS+jtkPCtOrbr+j8FU0Dgxh/5P0I2xR4hcgAAQKBgQDkcnwcaWRZv0uFxAtj\nq3pVelWuu3uapwroO9asmeWsmL3LQeW22X5CNy1gYOlhyG6FqfMLOmzhCicFYX45\n6EiDJpyX/LVcSDmzmTDwI25uEunhyhVATJWqwaITdLrJf8KDqqO8bvUHc/wB//2T\nOTWpUB542DZJ2A8aServjR6ErwKBgQD19l+5xCHLOldtV56hbAQnhhl8lUAL/mBq\nwXNrDNeqmDYFJ3kkHWk5raXUQR41qAubhKnLUJ4qj6FIBcRmsrTMITMWZ9/GzJhK\nmNU+nync2IlSS7g3Vyee3wz1Fd2dRA3NwZ9JVK+xTSKgw1a/VXKcfC+iYnXmVIxa\n3cCIZ9Um+QKBgQDE34Dj/1OzIG+WbPgfwiTgS1hSCFKiWfjFYORFxS8wykUuSLEO\nHmt35xNc7sfSNChDWs4QzB4O5m/wbC+a+fqbxAfJ18f4KmpHw+pv2SkPBY+3vS8J\nRbbp/IuP1tYuVsMsMz9+YeUasjLpClLesLv1GQ3ZuQM4KlIBptgn7+bwEwKBgQC1\nZDk8etShWClZziCC03JM46ywIDHXpoXctUY1UIdMnGxaaL4CUF5l1xZQ7qUk1QWa\nb7/43T+IC9zZjMdHJcwILwPKJlj197TobsX1JNRutpKvSoBU78WceMrJhJKnhKTZ\ndU3PetEHZOeAwA6dlJqtpThL/WkNsJTB/oAbGNgtoQKBgG4ytUXXwp61VHm/3Pon\n9d6z5o02AQVCppJRcJwehbAm14813G/jPfjwM+KZ2ikhs+eW1peWhBrCo+M5/u5T\nbxeDm9cbLMewkYNIdvUxtaBb+fJtIBAngAL2HEhqBdUFoQI+lr+F802UO2aM8Sg+\nn82S/+EJZomQ7hhO7qnLtxkI\n-----END PRIVATE KEY-----")

client_rsa_ct, client_aes_ct = collect_rsa_ct_and_aes_ct(client_arc4_pt)
server_rsa_ct, server_aes_ct = collect_rsa_ct_and_aes_ct(server_arc4_pt)

nums = len(client_rsa_ct)
for i in range(4):
    client_rsa_pt = rsa_decrypt(client_rsa_ct[i], server_rsa_sk)
    server_rsa_pt = rsa_decrypt(server_rsa_ct[i], client_rsa_sk)
    aes_key = strxor(client_rsa_pt, server_rsa_pt)
    client_aes_pt = aes_decrypt(client_aes_ct[i], aes_key)
    server_aes_pt = aes_decrypt(server_aes_ct[i], aes_key)
    print(client_aes_pt)
    print(server_aes_pt)

# rwctf{l1fe_1s_sh0rt_DO0_not_us3_rust}