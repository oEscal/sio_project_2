import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii

import random

length_by_cipher = {'ChaCha20': 32, 'AES': 32, 'TripleDES': 24}


def cipher_params(cipher_algorithm, key):

    algorithm = None
    iv = None
    iv_length = 16  # default value

    nonce = None  #Just used for ChaCha20

    cipher_mode = getattr(algorithms, cipher_algorithm)

    if cipher_mode.name == "ChaCha20":
        nonce = os.urandom(16)
        algorithm = cipher_mode(key, nonce)

    else:
        algorithm = cipher_mode(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)

    return algorithm, iv


def key_derivation(hash_algorithm, length, key):
    backend = default_backend()

    upper_hash_alg = hash_algorithm.upper()
    return HKDF(algorithm=getattr(hashes, upper_hash_alg)(),
                length=length,
                salt=None,
                info=b'handshake data',
                backend=backend).derive(key)


def encryption(data, key, cipher_algorithm, mode):

    algorithm, iv = cipher_params(cipher_algorithm, key)

    if iv is None:  #For ChaCha20
        iv_length = 16
    else:
        iv_length = len(iv)

    padding_length = (iv_length - (len(data) % iv_length)) % iv_length
    data += (padding_length * "\x00").encode()

    is_cha = False
    if iv is None:  # For ChaCha20
        cipher = Cipher(algorithm, None, backend=default_backend())
        iv = algorithm.nonce
        is_cha = True
    else:
        cipher = Cipher(algorithm,
                        getattr(modes, mode)(iv),
                        backend=default_backend())

    encryptor = cipher.encryptor()

    ct = encryptor.update(data) + encryptor.finalize()
    tag = None
    if mode == 'GCM' and not is_cha:
        tag = encryptor.tag

    return ct, padding_length, iv, tag


def decryption(data, key, cipher_algorithm, mode, padding_length, iv, tag):

    cipher_mode = getattr(algorithms, cipher_algorithm)
    if cipher_algorithm != 'ChaCha20':
        algorithm = cipher_mode(key)
    else:
        algorithm = cipher_mode(key, iv)

    if cipher_algorithm == 'ChaCha20':  # For ChaCha20
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
    else:
        cipher = Cipher(
            algorithm,
            mode=modes.CBC(iv)
            if mode == 'CBC' else modes.GCM(iv, tag),  #tentar melhorar isto
            backend=default_backend())

    decryptor = cipher.decryptor()

    output = decryptor.update(data) + decryptor.finalize()

    if padding_length == 0:
        return output

    return output[:-padding_length]


class ProtoAlgorithm:
    def __init__(self, cipher, mode, synthesis_algorithm):
        self.algorithm = "DH"  #Diffie-Hellman
        self.cipher = cipher
        self.mode = mode
        self.synthesis_algorithm = synthesis_algorithm

    def packing(self):
        return f"{self.algorithm}_{self.cipher}_{self.mode}_{self.synthesis_algorithm}"

    def __str__(self):
        return self.packing().replace('_', '\t')


def unpacking(pack_string):
    splitted_string = pack_string.split('_')
    return splitted_string[0], splitted_string[1], splitted_string[
        2], splitted_string[3]


def DH_parameters():
    return dh.generate_parameters(generator=2,
                                  key_size=1024,
                                  backend=default_backend())


def DH_parametersNumbers(p, g):
    pn = dh.DHParameterNumbers(p, g)
    return pn.parameters(default_backend())


def MAC(key, synthesis_algorithm):
    picked_hash = getattr(hashes, synthesis_algorithm)
    return hmac.HMAC(key, picked_hash(), backend=default_backend())
