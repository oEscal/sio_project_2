import os
from .hash_algorithms import HASHES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def symmetric_key_generation(hash_algorithm, key, length, salt_value=None):

    backend = default_backend()
    salt = os.urandom(16) if salt_value is None else salt_value
    number_iterations = 100000

    kdf = PBKDF2HMAC(
        algorithm=HASHES(hash_algorithm).get_hash(),
        length=length,
        salt=salt,
        iterations=number_iterations,
        backend=backend,
    )

    return kdf.derive(str.encode(key)), salt
