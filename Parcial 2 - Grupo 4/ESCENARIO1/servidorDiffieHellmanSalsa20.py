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

# Iniciar el servidor
def servidor():
    # Generar claves Diffie-Hellman
    clave_privada_servidor = generar_clave_privada(p)
    clave_publica_servidor = generar_clave_publica(p, g, clave_privada_servidor)

    # Configurar el socket del servidor
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_socket.bind(('localhost', 5555))
    servidor_socket.listen(1)

    print("Esperando conexión del cliente...")
    conexion, direccion = servidor_socket.accept()
    print(f"Conectado con {direccion}")

    # Enviar la clave pública del servidor al cliente
    conexion.sendall(str(clave_publica_servidor).encode())

    # Recibir la clave pública del cliente
    clave_publica_cliente = int(conexion.recv(1024).decode())

    # Calcular el secreto compartido
    secreto_compartido = pow(clave_publica_cliente, clave_privada_servidor, p)
    llave_simetrica = scrypt(str(secreto_compartido).encode(), b'sal', 32, N=2**14, r=8, p=1)

    print("Intercambio de claves completado. Secreto compartido establecido.")

    # Comunicación bidireccional
    while True:
        # Recibir mensaje cifrado del cliente
        nonce = conexion.recv(8)
        mensaje_cifrado = conexion.recv(1024)
        cipher = Salsa20.new(key=llave_simetrica, nonce=nonce)
        mensaje = cipher.decrypt(mensaje_cifrado)
        print(f"Cliente: {mensaje.decode()}")

        # Enviar respuesta
        mensaje_respuesta = input("Servidor: ").encode()
        cipher_respuesta = Salsa20.new(key=llave_simetrica)
        mensaje_respuesta_cifrado = cipher_respuesta.nonce + cipher_respuesta.encrypt(mensaje_respuesta)
        conexion.sendall(mensaje_respuesta_cifrado)

# Ejecutar el servidor
if __name__ == "__main__":
    servidor()
