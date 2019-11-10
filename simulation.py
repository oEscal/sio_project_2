from Symmetric_tools.encryption import encryption
from Symmetric_tools.decryption import decryption
from Symmetric_tools.Symmetric_key_generation import symmetric_key_generation
from Symmetric_tools.utils import cipher_params
from asymmetric_tools import *

import getpass


def main():
    key_length = 1024

    user_pass = getpass.getpass()

    private_key, public_key = key_pair_generation(key_length, user_pass)

    pub_key_file = open("public.pem", "wb")
    pub_key_file.write(public_key)
    pub_key_file.close()

    pri_key_file = open("private.pem", "wb")
    pri_key_file.write(private_key)
    pri_key_file.close()


    length = 32
    cipher_algorithm = "AES" #AES OR TripleDES

    '''
        ATENCÇAO :
        SE ESCOLHERES TRIPLEDES length = 24
        SE ESCOLHERES AES length = 32
    '''

    key, salt = symmetric_key_generation("SHA256", user_pass, length)

    algorithm, iv = cipher_params(cipher_algorithm, key)

    encryption("data.txt", "encrypted.txt", algorithm, iv, salt)

    f = open("file_key.bin", "wb")
    f.write(key)
    f.close()

    rsa_encryption("file_key.bin", "encrypted_file_key.bin")

    # DECRYPT

    rsa_decryption("file_key_decrypted.bin", "encrypted_file_key.bin")

    key = open("file_key_decrypted.bin", "rb").read()

    algorithm, iv = cipher_params(cipher_algorithm, key)

    decryption("encrypted.txt", "decrypted_file.out", algorithm)


if __name__ == "__main__":
    main()
