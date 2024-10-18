import socket
from Crypto.Random import random
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import Salsa20

# Configuración del intercambio de claves Diffie-Hellman
p = 23  # Un número primo pequeño para el ejemplo (debería ser mucho más grande en la realidad)
g = 5   # Generador

def generar_clave_privada(p):
    return random.randint(2, p - 1)

def generar_clave_publica(p, g, clave_privada):
    return pow(g, clave_privada, p)

# Iniciar el cliente
def cliente():
    # Generar claves Diffie-Hellman
    clave_privada_cliente = generar_clave_privada(p)
    clave_publica_cliente = generar_clave_publica(p, g, clave_privada_cliente)

    # Configurar el socket del cliente
    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente_socket.connect(('localhost', 5555))

    # Recibir la clave pública del servidor
    clave_publica_servidor = int(cliente_socket.recv(1024).decode())

    # Enviar la clave pública del cliente al servidor
    cliente_socket.sendall(str(clave_publica_cliente).encode())

    # Calcular el secreto compartido
    secreto_compartido = pow(clave_publica_servidor, clave_privada_cliente, p)
    llave_simetrica = scrypt(str(secreto_compartido).encode(), b'sal', 32, N=2**14, r=8, p=1)

    print("Intercambio de claves completado. Secreto compartido establecido.")
    print(llave_simetrica)
    # Comunicación bidireccional
    while True:
        # Enviar mensaje al servidor
        mensaje = input("Cliente: ").encode()
        cipher_cliente = Salsa20.new(key=llave_simetrica)
        mensaje_cifrado = cipher_cliente.nonce + cipher_cliente.encrypt(mensaje)
        cliente_socket.sendall(mensaje_cifrado)

        # Recibir respuesta cifrada del servidor
        nonce = cliente_socket.recv(8)
        mensaje_cifrado = cliente_socket.recv(1024)
        cipher_servidor = Salsa20.new(key=llave_simetrica, nonce=nonce)
        mensaje_descifrado = cipher_servidor.decrypt(mensaje_cifrado)
        print(f"Servidor: {mensaje_descifrado.decode()}")

# Ejecutar el cliente
if __name__ == "__main__":
    cliente()
