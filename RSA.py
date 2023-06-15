import random
import math
from hashlib import sha3_256
import sys
from hashlib import sha1
from os import urandom
from math import ceil
from operator import xor
sys.setrecursionlimit(1500)


def generateKeys():

    p = generatePrime(1024)
    q = generatePrime(1024)
    n = p * q
    x = (p-1) * (q-1)

    e = generateE(x)
    d = modularInversion(e, x)[1] % x

    public_key = [n, e]
    private_key = [n, d]

    return public_key, private_key


def generatePrime(size):

    while True:
        x = random.randrange(1 << (size - 1), (1 << size) - 1)
        if isPrime(x):
            return x


# Miller Rabin: method to verify prime numbers
def isPrime(n):
    k = 0
    m = n - 1

    while m % 2 == 0:
        k += 1
        m >>= 1

    for i in range(40):

        a = random.randrange(2, n - 1)
        x = pow(a, m, n)

        if x == 1 or x == n - 1:
            continue

        for j in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        return False

    return True


def generateE(x):
    while True:
        e = random.randrange(2, x)
        if math.gcd(x, e) == 1:
            break
    return e


# Euclides' algorithm implementation
def modularInversion(e, x):
    if e == 0:
        return x, 0, 1
    else:
        a, b, c = modularInversion(x % e, e)
        return a, c - (x // e) * b, b


def rsa(key, msg):
    n, exp = key
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(msg, "big")
    c = pow(m, exp, n)

    return c.to_bytes(k, "big")


def cipher(key, msg):
    cipher_text = cipher_oaep(key[0], msg)

    return rsa(key, cipher_text)


def decipher(key, cipher_text):
    msg = rsa(key, cipher_text)

    return decipher_oaep(key[0], msg)


def sign(private_key, data):
    hash = sha3_256(data).digest()
    return rsa(private_key, hash)


def verify_signature(public_key, data, signature):
    hash = sha3_256(data).digest()
    return rsa(public_key, signature)[-32:] == hash


# OAEP ----------------------------------------------
def cipher_oaep(n, session_key):
    k = (n.bit_length() + 7) // 8
    session_key_size = len(session_key)
    hash_size = 20

    lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"

    padding_string = b"\x00" * (k - session_key_size - 2 * hash_size - 2)

    data_block = lable_hash + padding_string + b'\x01' + session_key

    seed = urandom(hash_size)

    masked_data_block = mask(data_block, seed, k - hash_size - 1)
    masked_seed = mask(seed, masked_data_block, hash_size)

    return b'\x00' + masked_seed + masked_data_block


def decipher_oaep(n, cipher_msg):
    k = (n.bit_length() + 7) // 8
    hash_size = 20

    _, masked_seed, masked_data_block = cipher_msg[:1], cipher_msg[1:1 + hash_size], cipher_msg[1 + hash_size:]

    seed = mask(masked_seed, masked_data_block, hash_size)

    data_block = mask(masked_data_block, seed, k - hash_size - 1)

    _, msg = data_block.split(b'\x01')

    return msg


def mask(data, seed, mlen):
    txt = b''
    for i in range(ceil(mlen / 20)):
        c = i.to_bytes(4, "big")
        txt += sha1(seed + c).digest()

    return bytes(map(xor, data, bytes(len(data)) + txt[:mlen]))
