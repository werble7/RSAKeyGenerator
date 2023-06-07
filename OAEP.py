from hashlib import sha1
from os import urandom
from math import ceil
from operator import xor


def mask(data, seed, mlen):
    txt = b''
    for i in range(ceil(mlen / 20)):
        c = i.to_bytes(4, "big")
        txt += sha1(seed + c).digest()

    return bytes(map(xor, data, bytes(len(data)) + txt[:mlen]))


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
