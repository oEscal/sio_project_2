from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import getpass
import os

# pa ficheiros grandes nao se usa a assimetrica, porque é bue expensioso. O que se faz é uma cena hibrida, em que se cifra o ficheiro com uma
# mais simples(simetrica), e depois a chave com uma assimetrica; assim pa ter acesso ao file precis da assimetrica anyway
# tirei foto(lado esquerdo encriptar, direito desisncriptar)

def key_pair_generation(key_length):
   # TODO -> change this maybe
   pass_size = 37

   private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=key_length,
      backend=default_backend()
   )
   public_key = private_key.public_key()  

   # return private and public keys
   return private_key.private_bytes(  
      encoding=serialization.Encoding.PEM,  
      format=serialization.PrivateFormat.TraditionalOpenSSL,  
      encryption_algorithm=serialization.BestAvailableEncryption(os.urandom(pass_size))  
   ), public_key.public_bytes(  
      encoding=serialization.Encoding.PEM,  
      format=serialization.PublicFormat.SubjectPublicKeyInfo,
   )  


def rsa_encryption(origin, dest):
   with open("adeus.pem", "rb") as key_file:
      public_key = serialization.load_pem_public_key(
         key_file.read(),
         backend=default_backend()
      )

   with open(origin, "r") as origin_file:
      message = "".join(origin_file.readlines())

   encrypted = public_key.encrypt(
      message,
      padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
      )
   )

   with open(dest, "wb") as file:
      file.write(encrypted)

   print("Encryption done!")

def rsa_decryption(dest):
   file_name = "encrypted_text_with_public_key"

   with open(file_name, "rb") as file:
      encrypted_text = file.read(256)

   with open("ola.pem", "rb") as key_file:
      private_key = serialization.load_pem_private_key(
         key_file.read(),
         password=getpass.getpass().encode(),
         backend=default_backend()
      )

   decrypted = private_key.decrypt(
      encrypted_text,
      padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
      )
   )

   with open(dest, 'w') as file_save:
      file_save.write(decrypted.decode())

   print("Decryption done!")

#rsa_encryption('asymmetric_cryptography.py', 'encrypted_text_with_public_key')
#rsa_decryption('decrypted_text_with_private_key.txt')
