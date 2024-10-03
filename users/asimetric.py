from ecdsa import SigningKey, SECP256k1, VerifyingKey
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import binascii


class ECC:
    
    def __init__(self):
        # Generar la clave privada y pública del servidor
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.verifying_key

    def derive_shared_secret(self, server_private_key, client_public_key):
        # Convertir la clave pública del cliente de hexadecimal a bytes
        client_public_key_bytes = bytes.fromhex(client_public_key)
        # Obtener la clave pública del cliente a partir de los bytes
        client_public_key = VerifyingKey.from_string(client_public_key_bytes, curve=SECP256k1)
    
        # Derivar el secreto compartido multiplicando el secreto del servidor por el punto de la clave pública del cliente
        shared_secret = server_private_key.privkey.secret_multiplier * client_public_key.pubkey.point
        
        # Devolver el valor X del punto resultante como 32 bytes
        return shared_secret.x().to_bytes(32, byteorder="big")

    def encrypt_message(self, shared_secret, text):
            # Derivar la clave simétrica (AES) a partir del secreto compartido usando SHA-256
        key = sha256(shared_secret).digest()
        
        # Crear un vector de inicialización (IV) para el modo CBC
        iv = get_random_bytes(AES.block_size)
        
        # Crear el cifrador AES en modo CBC con el IV generado
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Cifrar el texto (agregar padding para que sea múltiplo del tamaño del bloque)
        ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
        
        encrypted_message = iv + ciphertext
        return binascii.hexlify(encrypted_message).decode('utf-8')


        def decrypt_message(shared_secret, encrypted_message):
        # Derivar la clave simétrica (AES) a partir del secreto compartido usando SHA-256
        key = sha256(shared_secret).digest()
        
        # Convertir el mensaje cifrado de hexadecimal a bytes
        encrypted_message_bytes = binascii.unhexlify(encrypted_message)
        
        # El primer bloque (del tamaño de AES.block_size) es el IV
        iv = encrypted_message_bytes[:AES.block_size]
        
        # El resto es el ciphertext
        ciphertext = encrypted_message_bytes[AES.block_size:]
        
        # Crear el descifrador AES en modo CBC con el IV extraído
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Descifrar el mensaje y eliminar el padding
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return plaintext.decode('utf-8')

