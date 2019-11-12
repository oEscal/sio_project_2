from utils import *
from asymmetric_tools import *

import getpass


def main():
    length = 32
    cipher_algorithm = "AES" #AES OR TripleDES

    '''
        ATENCÇAO :
        SE ESCOLHERES TRIPLEDES length = 24
        SE ESCOLHERES AES length = 32
    '''

    key, salt = symmetric_key_generation("SHA256", getpass.getpass(), length)

    algorithm, iv = cipher_params(cipher_algorithm, key)

    encryption("README.md", "encrypted.txt", algorithm, iv, salt)

    with open("file_key.bin", 'wb') as file:
        file.write(key)

if __name__ == "__main__":
    main()
