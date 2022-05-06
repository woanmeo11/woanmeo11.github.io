import jwt
import gmpy2
import requests

from hashlib import sha256
from base64 import urlsafe_b64decode
from Crypto.Util.number import bytes_to_long, inverse
from Crypto.PublicKey import RSA
from factordb.factordb import FactorDB

def pkcs1_v1_5_encode(msg: bytes, n_len: int):
    SHA256_Digest_Info = b'\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    T = SHA256_Digest_Info + sha256(msg).digest()
    PS = b'\xFF' * (n_len - len(T) - 3)
    return b'\x00\x01' + PS + b'\x00' + T

def get_magic(jwt):
    header, payload, signature = jwt.split(".")

    raw_signature = urlsafe_b64decode(f"{signature}==")
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature))

    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature))
    padded_int = gmpy2.mpz(bytes_to_long(padded_msg))

    e = gmpy2.mpz(0x10001)

    return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)

url = 'https://web-jwt-b9766b1f.chal-2021.duc.tf'

jwt0 = requests.get(url + '/get_token').text
jwt1 = requests.get(url + '/get_token').text
print('jwt0: ', jwt0)
print('jwt1: ', jwt1)

magic0 = get_magic(jwt0)
magic1 = get_magic(jwt1)

g = gmpy2.gcd(magic0, magic1)
print('gcd: ', g)

factors = FactorDB(g)
factors.connect()
factors = factors.get_factor_list()
print('factors: ', factors)

p, q = factors[-2:]
N = p * q
print('N: ', N)

e = 0x10001
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((N, e, d))
priv_key = key.export_key('PEM')
print('priv_key:\n', priv_key.decode())

forged_jwt = jwt.encode({'admin': True}, priv_key, algorithm='RS256')
print('forged jwt: ', forged_jwt.decode())

flag = requests.post(url + '/get_flag', data={ 'jwt': forged_jwt }).text
print('flag: ', flag)
