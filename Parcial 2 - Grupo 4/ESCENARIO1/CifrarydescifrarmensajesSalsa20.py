from Crypto.Cipher import Salsa20

# Nonce y mensaje interceptado
nonce = bytes.fromhex("0833ed81cb907456")  # Nonce interceptado
mensaje_cifrado = bytes.fromhex("3ccba2000800450028e967400800c0a8010734a87042cf01bb1aacb08a5c57743250140066b40000")  # Mensaje cifrado interceptado

# Clave simétrica que has proporcionado
llave_simetrica = b'\x83|+_\xf0\xe2\xab\x1a\xab\x98y\xca\x03_>\x99C\xf7\xcf\xaf\x0f\xf3\\\xce\xe2\x91\xd1\xd7\x0f\xb5\x1e>'

# Crear el cifrador Salsa20 usando el nonce interceptado
cipher = Salsa20.new(key=llave_simetrica, nonce=nonce)

# Descifrar el mensaje
mensaje_descifrado = cipher.decrypt(mensaje_cifrado)

print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")
