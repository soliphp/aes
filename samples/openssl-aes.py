#!/usr/bin/python2
"""
Copyright 2013 Christophe-Marie Duquesne <chmd@chmd.fr>

This file is in PUBLIC DOMAIN.

It contains function to Encrypt/Decrypt text in an openssl compatible way,
with minimal dependencies (pycrypto). See the functions aes_encrypt/aes_decrypt.
"""

import sys
import select
from base64 import b64decode, b64encode
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Hash import MD5
# (!) We use a crypto-secure randint function
from Crypto.Random.random import randint

def random_salt(n=8):
    """Generate an 8 random bytes salt"""
    res = ''
    for i in range(n):
        res += chr(randint(0,255))
    return res

def derive_key_and_iv(secret, salt):
    """Derives a key and an iv from the password and the salt, using
    opensssl non standard method"""
    hash_1 = MD5.new(secret+salt).digest()
    hash_2 = MD5.new(hash_1+secret+salt).digest()
    hash_3 = MD5.new(hash_2+secret+salt).digest()
    mat = hash_1 + hash_2 + hash_3

    key = mat[0:32]
    iv  = mat[32:48]
    return (iv, key)

def aes_decrypt(secret, encrypted_text):
    """Decrypt the text. Does the same thing as:
    echo <encrypted_text> | openssl aes-256-cbc -d -base64 -pass pass:<secret>
    """
    encrypted = b64decode(encrypted_text)
    salt = encrypted[8:16]
    data = encrypted[16:]
    iv, key = derive_key_and_iv(secret, salt)
    cypher = AES.new(key, AES.MODE_CBC, iv)
    text = cypher.decrypt(data)
    return text

def aes_encrypt(secret, text):
    """Encrypt the text. Does the same thing as:
    echo <encrypted_text> | openssl aes-256-cbc -d -base64 -pass pass:<secret>
    """
    salt = random_salt()
    iv, key = derive_key_and_iv(secret, salt)
    cypher = AES.new(key, AES.MODE_CBC, iv)
    # PKCS#7: padd with n, where n is the number of characters remaining
    # to reach a multiple of 16.
    n = 16 - len(text) % 16
    text += chr(n) * n
    encrypted = cypher.encrypt(text)
    return b64encode('Salted__' + salt + encrypted)

def main():
    if (not select.select([sys.stdin,],[],[],0.0)[0] or len(sys.argv)!= 3
            or sys.argv[1] not in ("encrypt", "decrypt")):
        print "Usage: echo text | ./aes.py [decrypt|decrypt] <password>"
        exit(2)
    # Get the input data from stdin
    datain = ""
    for line in sys.stdin:
        datain += line
    # Get the password
    password = sys.argv[2]
    # Encrypt/decrypt
    if sys.argv[1] == "encrypt":
        sys.stdout.write(aes_encrypt(password, datain))
        sys.stdout.write("\n")
    if sys.argv[1] == "decrypt":
        sys.stdout.write(aes_decrypt(password, datain))

if __name__ == "__main__":
    main()
