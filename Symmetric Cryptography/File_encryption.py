from utils import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def file_encryption(
    user_file, encrypted_file, encryption_algorithm, hash_algorithm="SHA256"
):

    params = cipher_params(encryption_algorithm, hash_algorithm)

    f = open(user_file, "r")
    file_content = f.read()
    file_length = len(file_content)
    f.close()

    cipher = Cipher(
        params["algorithm"], modes.CBC(params["iv"]), backend=default_backend()
    )

    iv_length = params["iv_length"]
    padding_length = (iv_length - (file_length % iv_length)) % iv_length
    file_content += padding_length * "\x00"

    encryptor = cipher.encryptor()
    # TODO -> read file in blobs
    ct = encryptor.update(str.encode(file_content))  + encryptor.finalize() 
    
    symmetric_protocol = Symmetric_protocol(
        params["iv"], params["salt"], padding_length, ct
    )

    cryptogram_file = open(encrypted_file, "wb")
    write_protocol(symmetric_protocol, cryptogram_file)
    cryptogram_file.close()
