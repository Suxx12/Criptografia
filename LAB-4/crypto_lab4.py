import base64
from typing import Tuple

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("Entrada vacía para unpadding")
    padding_length = padded[-1]
    if padding_length < 1 or padding_length > len(padded):
        raise ValueError("Padding PKCS#7 inválido")
    if padded[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Padding PKCS#7 corrupto")
    return padded[:-padding_length]


def adjust_length(key_bytes: bytes, target_len: int) -> bytes:
    if len(key_bytes) == target_len:
        return key_bytes
    if len(key_bytes) < target_len:
        return key_bytes + get_random_bytes(target_len - len(key_bytes))
    return key_bytes[:target_len]


def prepare_des_key(user_key: bytes) -> bytes:
    # DES requiere 8 bytes; la biblioteca maneja paridad internamente
    return adjust_length(user_key, 8)


def prepare_des3_key(user_key: bytes) -> bytes:
    # 3DES acepta 16 o 24 bytes. Usaremos 24 bytes por seguridad.
    key = adjust_length(user_key, 24)
    # Ajuste de paridad y validación de clave débil
    try:
        key = DES3.adjust_key_parity(key)
        # Probar construcción para validar que no es clave débil
        DES3.new(key, DES3.MODE_ECB)
    except ValueError:
        # Si es inválida, regenerar últimos 8 bytes de forma aleatoria y reintentar
        regenerated = key[:16] + get_random_bytes(8)
        regenerated = DES3.adjust_key_parity(regenerated)
        DES3.new(regenerated, DES3.MODE_ECB)
        key = regenerated
    return key


def prepare_aes256_key(user_key: bytes) -> bytes:
    return adjust_length(user_key, 32)


def prepare_iv(user_iv: bytes, block_size: int) -> bytes:
    return adjust_length(user_iv, block_size)


def encrypt_cbc(algorithm: str, key: bytes, iv: bytes, plaintext: str) -> Tuple[str, str]:
    data = plaintext.encode("utf-8")

    if algorithm == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        block_size = 8
    elif algorithm == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        block_size = 8
    elif algorithm == "AES-256":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        block_size = 16
    else:
        raise ValueError("Algoritmo no soportado")

    padded = pkcs7_pad(data, block_size)
    ciphertext = cipher.encrypt(padded)

    # Descifrar para validar
    decipher = None
    if algorithm == "DES":
        decipher = DES.new(key, DES.MODE_CBC, iv=iv)
    elif algorithm == "3DES":
        decipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    else:
        decipher = AES.new(key, AES.MODE_CBC, iv=iv)

    recovered = pkcs7_unpad(decipher.decrypt(ciphertext)).decode("utf-8")

    return base64.b64encode(ciphertext).decode("ascii"), recovered


def ask_bytes(prompt: str) -> bytes:
    text = input(prompt).strip()
    # Permitir entrada en hex (prefijo 0x) o base64 (prefijo b64:)
    if text.startswith("0x"):
        return bytes.fromhex(text[2:])
    if text.startswith("b64:"):
        return base64.b64decode(text[4:])
    return text.encode("utf-8")


def main() -> None:
    print("=== LAB4 - Cifrado Simétrico CBC (DES, 3DES, AES-256) ===")
    print("Notas:")
    print("- Puede ingresar claves/IV como texto, hex (0x...) o base64 (b64:...)")
    print("- El programa ajustará longitudes (relleno aleatorio o truncado) según el algoritmo")
    print()

    plaintext = input("Texto a cifrar: ").strip()

    # DES
    print("\n--- DES (CBC) ---")
    des_key_user = ask_bytes("Key DES (8 bytes requeridos): ")
    des_iv_user = ask_bytes("IV DES (8 bytes requeridos): ")
    des_key = prepare_des_key(des_key_user)
    des_iv = prepare_iv(des_iv_user, 8)
    des_ct_b64, des_recovered = encrypt_cbc("DES", des_key, des_iv, plaintext)
    print(f"Key DES final (hex): {des_key.hex()}")
    print(f"IV DES final (hex): {des_iv.hex()}")
    print(f"Cifrado DES (base64): {des_ct_b64}")
    print(f"Descifrado DES: {des_recovered}")

    # 3DES
    print("\n--- 3DES (CBC) ---")
    tdes_key_user = ask_bytes("Key 3DES (24 bytes recomendados): ")
    tdes_iv_user = ask_bytes("IV 3DES (8 bytes requeridos): ")
    tdes_key = prepare_des3_key(tdes_key_user)
    tdes_iv = prepare_iv(tdes_iv_user, 8)
    tdes_ct_b64, tdes_recovered = encrypt_cbc("3DES", tdes_key, tdes_iv, plaintext)
    print(f"Key 3DES final (hex): {tdes_key.hex()}")
    print(f"IV 3DES final (hex): {tdes_iv.hex()}")
    print(f"Cifrado 3DES (base64): {tdes_ct_b64}")
    print(f"Descifrado 3DES: {tdes_recovered}")

    # AES-256
    print("\n--- AES-256 (CBC) ---")
    aes_key_user = ask_bytes("Key AES-256 (32 bytes requeridos): ")
    aes_iv_user = ask_bytes("IV AES (16 bytes requeridos): ")
    aes_key = prepare_aes256_key(aes_key_user)
    aes_iv = prepare_iv(aes_iv_user, 16)
    aes_ct_b64, aes_recovered = encrypt_cbc("AES-256", aes_key, aes_iv, plaintext)
    print(f"Key AES-256 final (hex): {aes_key.hex()}")
    print(f"IV AES final (hex): {aes_iv.hex()}")
    print(f"Cifrado AES-256 (base64): {aes_ct_b64}")
    print(f"Descifrado AES-256: {aes_recovered}")


if __name__ == "__main__":
    main()


