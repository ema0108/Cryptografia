import time
from rsa_oaep import cifrar_rsa_oaep, descifrar_rsa_oaep, generar_llaves_rsa
from elgamal import cifrar_elgamal, descifrar_elgamal, generar_llaves_elgamal, cargar_llave_publica, cargar_llave_privada
from Crypto.Cipher import Salsa20, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

generar_llaves_rsa()
generar_llaves_elgamal()

BLOCK_SIZE = 16
mensaje = b'Test to see which cipher is better. A comparison between SYMMETRIC & ASYMMETRIC'
with open('resultados_comparativa.txt', 'w') as f:

    f.write("-------- RSA OAEP --------\n")
    start_time = time.time()
    ciphertext_rsa = cifrar_rsa_oaep(mensaje)
    cifrado_rsa_time = (time.time() - start_time) * 1000
    start_time = time.time()
    mensaje_descifrado_rsa = descifrar_rsa_oaep(ciphertext_rsa)
    descifrado_rsa_time = (time.time() - start_time) * 1000
    f.write(f"Longitud mensaje cifrado: {len(ciphertext_rsa) * 8} bits\n")
    f.write(f"Tiempo cifrado: {cifrado_rsa_time:.3f} ms\n")
    f.write(f"Tiempo descifrado: {descifrado_rsa_time:.3f} ms\n\n")


    f.write("-------- ElGamal --------\n")
    public_key_elgamal = cargar_llave_publica()
    private_key_elgamal = cargar_llave_privada()
    
    start_time = time.time()
    ciphertext_elgamal = cifrar_elgamal(public_key_elgamal, mensaje.decode())
    cifrado_elgamal_time = (time.time() - start_time) * 1000
    a, b = ciphertext_elgamal
    longitud_elgamal = b.bit_length()
    start_time = time.time()
    mensaje_descifrado_elgamal = descifrar_elgamal(private_key_elgamal, ciphertext_elgamal, public_key_elgamal)
    descifrado_elgamal_time = (time.time() - start_time) * 1000
    f.write(f"Longitud mensaje cifrado: {longitud_elgamal} bits\n")
    f.write(f"Tiempo cifrado: {cifrado_elgamal_time:.3f} ms\n")
    f.write(f"Tiempo descifrado: {descifrado_elgamal_time:.3f} ms\n\n")


    f.write("-------- Salsa20 --------\n")
    key = get_random_bytes(32)
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce

    start_time = time.time()
    ciphertext_salsa20 = cipher.encrypt(mensaje)
    cifrado_salsa20_time = (time.time() - start_time) * 1000
    cipher_dec_salsa20 = Salsa20.new(key=key, nonce=nonce)
    start_time = time.time()
    mensaje_descifrado_salsa20 = cipher_dec_salsa20.decrypt(ciphertext_salsa20)
    descifrado_salsa20_time = (time.time() - start_time) * 1000
    f.write(f"Longitud del mensaje cifrado: {len(ciphertext_salsa20) * 8} bits\n")
    f.write(f"Tiempo de cifrado: {cifrado_salsa20_time:.3f} ms\n")
    f.write(f"Tiempo de descifrado: {descifrado_salsa20_time:.3f} ms\n\n")


    f.write("-------- AES-256 CBC --------\n")
    key_aes = get_random_bytes(32)
    cipher_aes = AES.new(key_aes, AES.MODE_CBC)
    iv = cipher_aes.iv
    mensaje_padded = pad(mensaje, BLOCK_SIZE)

    start_time = time.time()
    ciphertext_aes = cipher_aes.encrypt(mensaje_padded)
    cifrado_aes_time = (time.time() - start_time) * 1000
    cipher_aes_dec = AES.new(key_aes, AES.MODE_CBC, iv)
    start_time = time.time()
    mensaje_descifrado_aes = unpad(cipher_aes_dec.decrypt(ciphertext_aes), BLOCK_SIZE)
    descifrado_aes_time = (time.time() - start_time) * 1000
    f.write(f"Longitud del mensaje cifrado: {len(ciphertext_aes) * 8} bits\n")
    f.write(f"Tiempo de cifrado: {cifrado_aes_time:.3f} ms\n")
    f.write(f"Tiempo de descifrado: {descifrado_aes_time:.3f} ms\n\n")

print("Comparativa completada. Resultados guardados en 'resultados_comparativa.txt'")