from Crypto.Random import random
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import Salsa20
import json

# Generación de claves Diffie-Hellman
def generar_clave_privada(p):
    return random.randint(2, p - 1)

def generar_clave_publica(p, g, clave_privada):
    return pow(g, clave_privada, p)

# Cargar parámetros de ejemplo (estos deben ser valores grandes en la práctica)
p = 23  # Número primo (en una implementación real, debe ser mucho más grande)
g = 5   # Generador del grupo

# Generar claves para el cliente y el servidor
clave_privada_cliente = generar_clave_privada(p)
clave_publica_cliente = generar_clave_publica(p, g, clave_privada_cliente)

clave_privada_servidor = generar_clave_privada(p)
clave_publica_servidor = generar_clave_publica(p, g, clave_privada_servidor)

# Cálculo del secreto compartido
secreto_compartido_cliente = pow(clave_publica_servidor, clave_privada_cliente, p)
secreto_compartido_servidor = pow(clave_publica_cliente, clave_privada_servidor, p)

# Derivación de la llave simétrica utilizando una KDF (scrypt)
llave_simetrica = scrypt(str(secreto_compartido_cliente).encode(), b'sal', 32, N=2**14, r=8, p=1)

print("Intercambio de claves completado. Secreto compartido derivado.")
