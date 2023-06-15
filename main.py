#!/usr/bin/python3

import base64
import secrets
from pathlib import Path
import AES
import RSA

public_key, private_key = [0, 0], [0, 0]
signature, session_key, session_key_cipher = b'', b'', b''

public_key_archive = Path(__file__).absolute().parent / "archives/public_key.txt"
private_key_archive = Path(__file__).absolute().parent / "archives/private_key.txt"
signature_file = Path(__file__).absolute().parent / 'archives/signature.txt'
session_key_cypher_file = Path(__file__).absolute().parent / 'archives/session_key_cypher.txt'

while True:
    op = int(input("Choose An Option:\n 1- Generate Keys\n 2- Read Saved Keys\n 3- Cipher"
                   "\n 4- Decipher\n 5- Exit\n"))

    # Generate public and private keys
    if op == 1:
        print("\nLoading keys...\n")

        public_key, private_key = RSA.generateKeys()

        with open(public_key_archive, "wb") as f:
            f.write(public_key[0].to_bytes(public_key[0].bit_length(), 'big'))
            f.write(public_key[1].to_bytes(public_key[1].bit_length(), 'big'))

        with open(private_key_archive, "wb") as f:
            f.write(private_key[0].to_bytes(private_key[0].bit_length(), 'big'))
            f.write(private_key[1].to_bytes(private_key[1].bit_length(), 'big'))

    # adding archives to save keys
    elif op == 2:

        with open(public_key_archive, "rb") as f:
            pubkey = f.read()

        with open(private_key_archive, "rb") as f:
            prvtkey = f.read()

        y = 0
        for x in pubkey.split(b'\x00\x00'):
            if x != b'':
                public_key[y] = int.from_bytes(x, 'big')
                y = 1

        y = 0
        for x in prvtkey.split(b'\x00\x00'):
            if x != b'':
                private_key[y] = int.from_bytes(x, 'big')
                y = 1

        if private_key == [0, 0] or public_key == [0, 0]:
            print("\nGenerate keys first\n")
            continue

        print(f'Public key:\nN: {public_key[0]}\nE: {public_key[1]}\n')
        print(f'Private key:\nN: {private_key[0]}\nD: {private_key[1]}\n')

    # Cipher and sign message
    elif op == 3:

        if private_key == [0, 0] or public_key == [0, 0]:
            print("\nGenerate keys first\n")
            continue

        try:
            key, iv = secrets.token_bytes(16), secrets.token_bytes(16)

            session_key = key + iv
            session_key_cipher = RSA.cipher(public_key, session_key)
            session_key_cipher = base64.b64encode(session_key_cipher).decode("ascii")

            arc = input('\nName of the file to be cipher: \n')
            file = Path(__file__).absolute().parent / 'archives' / arc

            with open(file, "rb") as f:
                msg = f.read()

            cipher_msg = AES.ctr(msg, key, iv)
            with open(file, "wb") as f:
                f.write(cipher_msg)

            signature = RSA.sign(private_key, msg)
            signature = base64.b64encode(signature).decode("ascii")

            with open(signature_file, 'wb') as f:
                f.write(bytes(signature, 'utf-8'))

            with open(session_key_cypher_file, 'wb') as f:
                f.write(bytes(session_key_cipher, 'utf-8'))

            print("\nsuccessfully encrypted\n")

        except FileNotFoundError:
            print("File not found, must be a typing error")

    # Decipher and verify cipher's signature
    elif op == 4:

        if private_key == [0, 0] or public_key == [0, 0]:
            print("\nGenerate keys first\n")
            continue

        try:
            arc = input('\nName of the file to be decipher:\n')
            file = Path(__file__).absolute().parent / 'archives' / arc

            with open(file, "rb") as f:
                cipher_msg = f.read()
            with open(signature_file, 'rb') as f:
                signature = f.read()
            with open(session_key_cypher_file, 'rb') as f:
                session_key_cipher = f.read()

            signature = base64.b64decode(signature)
            session_key_cipher = base64.b64decode(session_key_cipher)

            session_key = RSA.decipher(private_key, session_key_cipher)
            key, iv = session_key[:16], session_key[16:]

            msg = AES.ctr(cipher_msg, key, iv)
            check = RSA.verify_signature(public_key, msg, signature)

            if check:
                with open(file, "wb") as f:
                    f.write(msg)
                print("\nsuccessfully decrypted\n")
            else:
                print("\nSignature doesn't match\n")

        except FileNotFoundError:
            print("File not found, must be a typing error")

    # Stop the program
    elif op == 5:
        break
    else:
        continue
