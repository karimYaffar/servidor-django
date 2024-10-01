from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .simetric import encrypt_3des
from .asimetric import ECC
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import hashlib


ecc =ECC()

# Funciones de hash
def hash_sha224(value):
    return hashlib.sha224(value.encode()).hexdigest()

def hash_sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()

def hash_sha384(value):
    return hashlib.sha384(value.encode()).hexdigest()

def hash_sha512(value):
    return hashlib.sha512(value.encode()).hexdigest()


@api_view(['GET'])
def generate_3des_key(request):
    try:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        
        return Response({
            "des_key": key.hex()
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "error": f"Error al generar la clave 3DES: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_public_key(request):
    try:
        public_key = ecc.public_key
        
        return Response({
            "public_key": public_key.to_string().hex(),
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            "error": f"Error al agenerar la clave 3DES: {str(e)}",
        },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    

@api_view(['POST'])
def encrypt_fields(request):
    # Obtener los datos de la solicitud
    field_value = request.data.get("fields")
    encrypt_type = request.data.get("encryption_type")
    key = request.data.get("key")  # Clave en hexadecimal para cifrado simétrico
    
    # Validar si 'fields' y 'encryption_type' están presentes
    if not field_value or not encrypt_type:
        return Response({
            "error": "Los campos 'fields' y 'encryption_type' son requeridos."
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Diccionario para almacenar los campos encriptados
    encrypt_fields = {}
    
    # Iterar sobre los campos y aplicar el cifrado correspondiente
    for field, value in field_value.items():
        try:
            if encrypt_type == "simetric":
                if not key:
                    return Response({
                        "error": "La clave 'key' es requerida para el cifrado simétrico."
                    }, status=status.HTTP_400_BAD_REQUEST)
                encrypt_value = encrypt_3des(value, key)  
            elif encrypt_type == "asimetric":
                if not key:
                    return Response({
                        "error": "La clave 'key' es requerida para el cifrado asimetrico"
                    }, status=status.HTTP_400_BAD_REQUEST)
                print("Dentro del if")
                shared_secret = ecc.derive_shared_secret(ecc.private_key, key)
                encrypt_value = ecc.encrypt_message(shared_secret, value)
            elif encrypt_type == "sha224":
                encrypt_value = hash_sha224(value)
            elif encrypt_type == "sha256":
                encrypt_value = hash_sha256(value)
            elif encrypt_type == "sha384":
                encrypt_value = hash_sha384(value)
            elif encrypt_type == "sha512":
                encrypt_value = hash_sha512(value)
            else:
                return Response({
                    "error": "Tipo de cifrado no soportado."
                }, status=status.HTTP_400_BAD_REQUEST)
                
            # Almacenar el campo encriptado en el diccionario
            encrypt_fields[field] = encrypt_value
            
        except Exception as e:
            print(f"Error: {str(e)} '{key}'")
            return Response({
                "error": f"Error al encriptar el campo '{field}': {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Devolver los campos originales y los cifrados
    return Response({
        "original_fields": field_value,
        "encrypted_fields": encrypt_fields,
        "encryption_type": encrypt_type
    }, status=status.HTTP_200_OK)

