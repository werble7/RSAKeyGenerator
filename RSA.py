import random
import math
from hashlib import sha3_256
import sys
import OAEP

sys.setrecursionlimit(1500)


def generateKeys():

    p = generatePrime(1024)
    q = generatePrime(1024)
    n = p * q
    x = (p-1) * (q-1)

    e = generateE(x)
    d = modularInversion(e, x)[1] % x

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def generatePrime(size):

    while True:
        x = random.randrange(1 << (size - 1), (1 << size) - 1)
        if isPrime(x):
            return x


# Miller Rabin: method to test prime numbers
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
    cipher_text = OAEP.cipher_oaep(key[0], msg)

    return rsa(key, cipher_text)


def decipher(key, cipher_text):
    msg = rsa(key, cipher_text)

    return OAEP.decipher_oaep(key[0], msg)


def sign(private_key, data):
    hash = sha3_256(data).digest()
    return rsa(private_key, hash)


def verify_signature(public_key, data, signature):
    hash = sha3_256(data).digest()
    return rsa(public_key, signature)[-32:] == hash
