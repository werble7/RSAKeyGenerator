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
    tam_chaveSes = len(session_key)
    tam_hash = 20

    lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"

    padding_string = b"\x00" * (k - tam_chaveSes - 2 * tam_hash - 2)

    data_block = lable_hash + padding_string + b'\x01' + session_key

    seed = urandom(tam_hash)

    masked_data_block = mask(data_block, seed, k - tam_hash - 1)
    masked_seed = mask(seed, masked_data_block, tam_hash)

    return b'\x00' + masked_seed + masked_data_block


def decipher_oaep(n, cipher_msg):
    k = (n.bit_length() + 7) // 8
    tam_hash = 20

    _, masked_seed, masked_data_block = cipher_msg[:1], cipher_msg[1:1 + tam_hash], cipher_msg[1 + tam_hash:]

    seed = mask(masked_seed, masked_data_block, tam_hash)

    data_block = mask(masked_data_block, seed, k - tam_hash - 1)

    _, msg = data_block.split(b'\x01')

    return msg
