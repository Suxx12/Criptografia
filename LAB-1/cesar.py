#!/usr/bin/env python3
import sys

def caesar(text: str, shift: int) -> str:
    shift = shift % 26
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)  # espacios, signos, etc. se conservan
    return ''.join(result)

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
        print("Ejemplo: python3 cesar.py \"hola mundo\" 3")
        sys.exit(1)

    # Tomamos el último argumento como corrimiento y el resto como texto
    try:
        shift = int(sys.argv[-1])
    except ValueError:
        print("El último argumento debe ser un número entero (corrimiento).")
        sys.exit(1)

    text = ' '.join(sys.argv[1:-1])
    encrypted = caesar(text, shift)
    print(encrypted)

if __name__ == "__main__":
    main()
