from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt_3des(plaintext, key_hex):
    try:
        # Convertir la clave de hexadecimal a bytes
        key = binascii.unhexlify(key_hex)
        
        # Ajustar los bits de paridad de la clave para 3DES
        key = DES3.adjust_key_parity(key)

        # Verificar la longitud de la clave (debe ser de 24 bytes)
        if len(key) != 24:
            raise ValueError("La clave 3DES debe tener 24 bytes.")

        # Crear el cifrador 3DES en modo ECB (o usa CBC si prefieres mayor seguridad)
        cipher = DES3.new(key, DES3.MODE_ECB)
        
        # Añadir padding para que el mensaje tenga un tamaño múltiplo del tamaño del bloque
        padded_data = pad(plaintext.encode('utf-8'), DES3.block_size)
        
        # Cifrar los datos
        encrypted_data = cipher.encrypt(padded_data)
        
        # Retornar el dato cifrado en formato hexadecimal
        return binascii.hexlify(encrypted_data).decode('utf-8')

    except ValueError as ve:
        raise ve
    except Exception as e:
        raise Exception(f"Error al cifrar con 3DES: {str(e)}")
# Función para descifrar con 3DES
def decrypt_3des(key, encrypted_data):
    # Crear el cifrador 3DES en modo ECB
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    # Descifrar el texto
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Remover el padding
    unpadded_data = unpad(decrypted_data, DES3.block_size)
    
    return unpadded_data