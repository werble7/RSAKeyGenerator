#!/usr/bin/python3

import base64
import secrets
from pathlib import Path
import AES
import RSA

public_key, private_key = (0, 0), (0, 0)
signature, session_key, session_key_cipher = b'', b'', b''

while True:
    op = int(input("Choose An Option:\n 1- Generate Keys\n 2- Cipher\n 3- Decipher\n 4- Exit\n"))

    # Generate public and private keys
    if op == 1:
        public_key, private_key = RSA.generateKeys()

        print(f'Public key:\nN: {public_key[0]}\nE: {public_key[1]}\n')
        print(f'Private key:\nN: {private_key[0]}\nD: {private_key[1]}\n')

        public_key_archive = Path(__file__).absolute().parent / "public_key.txt"
        private_key_archive = Path(__file__).absolute().parent / "private_key.txt"

        with open(public_key_archive, "wb") as f:
            f.write(public_key[0].to_bytes(public_key[0].bit_length(), 'big'))
            f.write(public_key[1].to_bytes(public_key[1].bit_length(), 'big'))

        with open(private_key_archive, "wb") as f:
            f.write(private_key[0].to_bytes(private_key[0].bit_length(), 'big'))
            f.write(private_key[1].to_bytes(private_key[1].bit_length(), 'big'))

    # Cipher and sign message
    elif op == 2:

        if private_key == (0, 0) or public_key == (0, 0):
            print("Generate keys first")
            continue

        key, iv = secrets.token_bytes(16), secrets.token_bytes(16)

        session_key = key + iv
        session_key_cipher = RSA.cipher(public_key, session_key)
        session_key_cipher = base64.b64encode(session_key_cipher).decode("ascii")

        arc = input('\nName of the archive to be cipher: \n')
        archive = Path(__file__).absolute().parent / arc
        with open(archive, "rb") as f:
            msg = f.read()

        cipher_msg = AES.ctr(msg, key, iv)
        with open(archive, "wb") as f:
            f.write(cipher_msg)

        signature = RSA.sign(private_key, msg)
        signature = base64.b64encode(signature).decode("ascii")

        print("\nMessage:\n")
        print(msg, '\n')
        print('\nCipher message:\n')
        print(cipher_msg, '\n')
        print("\nSession's key:\n")
        print(session_key, '\n')
        print("\nCipher session's key:\n")
        print(session_key_cipher, '\n')
        print('\nSignature:\n')
        print(signature, '\n')

    # Decipher and verify cipher's signature
    elif op == 3:

        if private_key == (0, 0) or public_key == (0, 0):
            print("Generate keys first")
            continue

        arc = input('\nName of the archive to be decipher:\n')
        print()
        file = Path(__file__).absolute().parent / arc
        with open(file, "rb") as f:
            cipher_msg = f.read()
       
        signature = base64.b64decode(signature)
        session_key_cipher = base64.b64decode(session_key_cipher)
        
        session_key = RSA.decipher(private_key, session_key_cipher)
        key, iv = session_key[:16], session_key[16:]

        msg = AES.ctr(cipher_msg, key, iv)
        check = RSA.verify_signature(public_key, msg, signature)

        if check:
            print("\nSignature matches\n")
            print('Message:\n')
            print(msg)
            archive = Path(__file__).absolute().parent / arc
            with open(archive, "wb") as f:
                f.write(msg)
        else:
            print("\nSignature doesn't match\n")

    # Stop the program
    elif op == 4:
        break

    else:
        continue
