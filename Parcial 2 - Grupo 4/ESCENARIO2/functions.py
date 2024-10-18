import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes



HEADER_SIZE = 64
ENCODING = "utf-8"
DISCONNECT_MESSAGE = "BYE"
AES_BLOCK_SIZE = 16  # Tamaño del bloque de AES para CBC

def encrypt_message(key, message):
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = message + b' ' * (AES_BLOCK_SIZE - len(message) % AES_BLOCK_SIZE)
    ciphertext = iv + cipher.encrypt(padded_message)
    return ciphertext


# Descifrar un mensaje con AES-256-CBC
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_message[AES_BLOCK_SIZE:]).rstrip(b' ')
    return plaintext


def ecdh_shared_secret(private_key, public_key):
    point = public_key.pointQ
    shared_point = point * Integer(private_key.d)
    return int(shared_point.x)


# Generar clave privada y pública ECC (curva P256)
def generate_ecc_keys():
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()
    return private_key, public_key


# Derivar una clave simétrica a partir del secreto compartido usando HKDF
def derive_symmetric_key(shared_secret):
    derived_key = HKDF(shared_secret, 32, b"", SHA256)
    return derived_key


def conectedToClient(ClientConn, addr):

    # Intercambio de llaves Diffie-Hellman (ECC P-256)
    server_private_key, server_public_key = generate_ecc_keys()

    # Enviar la clave pública del servidor al cliente
    server_public_key_bytes = server_public_key.export_key(format="DER")
    server_public_key_length = str(len(server_public_key_bytes)).encode(ENCODING)
    server_public_key_length += b" " * (HEADER_SIZE - len(server_public_key_length))
    ClientConn.send(server_public_key_length)
    ClientConn.send(server_public_key_bytes)

    # Recibir la clave pública del cliente
    client_public_key_length = int(ClientConn.recv(HEADER_SIZE).decode(ENCODING))
    client_public_key_bytes = ClientConn.recv(client_public_key_length)
    client_public_key = ECC.import_key(client_public_key_bytes)

    # Generar el secreto compartido usando el intercambio manual
    shared_secret = ecdh_shared_secret(server_private_key, client_public_key)
    symmetric_key = derive_symmetric_key(str(shared_secret).encode())

    return symmetric_key


def connectedToServer(client):
    # Generar clave privada y pública ECC (curva P-256)
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()

    # Enviar la clave pública serializada (en formato DER) al servidor
    public_key_bytes = public_key.export_key(format="DER")
    public_key_length = str(len(public_key_bytes)).encode(ENCODING)
    public_key_length += b" " * (HEADER_SIZE - len(public_key_length))
    client.send(public_key_length)  # Enviar la longitud primero
    client.send(public_key_bytes)  # Luego enviar la clave pública

    # Recibir la longitud de la clave pública del servidor
    server_public_key_length = int(client.recv(HEADER_SIZE).decode(ENCODING))
    server_public_key_bytes = client.recv(server_public_key_length)  # Recibir la clave pública del servidor
    server_public_key = ECC.import_key(server_public_key_bytes)  # Importar la clave pública del servidor

    # Generar el secreto compartido usando el intercambio manual
    shared_secret = ecdh_shared_secret(private_key, server_public_key)

    # Derivar clave AES usando HKDF
    derived_key = HKDF(
        str(shared_secret).encode(), 32, b"", SHA256
    )  # Clave AES de 256 bits

    return derived_key


def exchange_keys_with_client(client_conn):
    print("MitM --> Realizando intercambio de claves con el cliente...")
    attacker_private_key, attacker_public_key = generate_ecc_keys()

    # Recibir la clave pública del cliente
    client_pub_key_len = int(client_conn.recv(HEADER_SIZE).decode(ENCODING))
    client_pub_key_bytes = client_conn.recv(client_pub_key_len)
    client_public_key = ECC.import_key(client_pub_key_bytes)

    # Enviar clave pública falsa del atacante al cliente
    attacker_pub_key_bytes = attacker_public_key.export_key(format='DER')
    client_conn.send(str(len(attacker_pub_key_bytes)).encode(ENCODING).ljust(HEADER_SIZE))
    client_conn.send(attacker_pub_key_bytes)

    return attacker_private_key, client_public_key

def exchange_keys_with_server(server_conn):
    print("MitM --> Realizando intercambio de claves con el servidor...")
    server_private_key, server_public_key = generate_ecc_keys()

    # Recibir la clave pública del servidor
    server_pub_key_len = int(server_conn.recv(HEADER_SIZE).decode(ENCODING))
    server_pub_key_bytes = server_conn.recv(server_pub_key_len)
    server_public_key = ECC.import_key(server_pub_key_bytes)

    # Enviar clave pública falsa del atacante al servidor
    server_pub_key_bytes = server_public_key.export_key(format='DER')
    server_conn.send(str(len(server_pub_key_bytes)).encode(ENCODING).ljust(HEADER_SIZE))
    server_conn.send(server_pub_key_bytes)

    return server_private_key, server_public_key

def derive_shared_secrets(attacker_private_key, client_public_key, server_private_key, server_public_key):
    shared_secret_with_client = ecdh_shared_secret(attacker_private_key, client_public_key)
    shared_secret_with_server = ecdh_shared_secret(server_private_key, server_public_key)

    aes_key_client = derive_symmetric_key(str(shared_secret_with_client).encode())
    aes_key_server = derive_symmetric_key(str(shared_secret_with_server).encode())

    print("MitM --> Secretos compartidos y claves derivadas generadas con éxito.")
    return aes_key_client, aes_key_server