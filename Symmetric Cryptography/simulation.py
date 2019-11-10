from encryption import encryption
from decryption import decryption


def main():
    encryption("big_data.txt", "encrypted.txt", "3DES", "SHA256")
    decryption("encrypted.txt", "decrypted_file.out", "3DES", "SHA256")


if __name__ == "__main__":
    main()
