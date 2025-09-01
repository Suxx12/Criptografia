#!/usr/bin/env python3
import sys
import subprocess
import os

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 readv2.py <archivo_pcap>")
        print("Ejemplo: python3 readv2.py captura.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"Error: Archivo {pcap_file} no encontrado")
        sys.exit(1)
    
    print("=== Analizador de Mensajes ICMP ===")
    print(f"Analizando archivo: {pcap_file}")
    print("-" * 50)
    
    # Extract characters from pcap file
    captured_chars = extract_characters(pcap_file)
    
    if not captured_chars:
        print("No se encontraron caracteres en el archivo")
        print("Usando mensaje de prueba...")
        captured_chars = "larycxpajorj h bnpdarmjm nw anmnb"
    
    print(f"Mensaje capturado: '{captured_chars}'")
    print(f"Longitud: {len(captured_chars)} caracteres")
    print("-" * 50)
    
    # Try all possible shifts
    print("Probando todos los corrimientos posibles:")
    print()
    
    most_probable = None
    best_score = 0
    
    for shift in range(26):
        decrypted = decrypt_caesar(captured_chars, shift)
        score = calculate_probability(decrypted)
        
        # Check if this is the most probable
        if score > best_score:
            best_score = score
            most_probable = (shift, decrypted)
        
        # Print with color if it's the most probable
        if score == best_score and score > 0:
            print(f"\033[92m{shift:2d}: {decrypted}\033[0m")  # Green
        else:
            print(f"{shift:2d}: {decrypted}")
    
    print("-" * 50)
    if most_probable:
        shift, message = most_probable
        print(f"\033[92mMensaje más probable (corrimiento {shift}): {message}\033[0m")
    else:
        print("No se pudo determinar el mensaje más probable")

def extract_characters(pcap_file):
    """Extract hidden characters from pcap file"""
    try:
        # Try different tshark paths
        tshark_paths = [
            "tshark",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ]
        
        for tshark_path in tshark_paths:
            try:
                result = subprocess.run([
                    tshark_path, "-r", pcap_file, 
                    "-T", "fields", "-e", "icmp.seq", "-e", "data"
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    return process_tshark_output(result.stdout)
                    
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        # If tshark fails, try with scapy
        return extract_with_scapy(pcap_file)
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def process_tshark_output(output):
    """Process tshark output to extract characters"""
    lines = output.strip().split('\n')
    captured_chars = []
    sequence_numbers = []
    
    for line in lines:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                seq = parts[0]
                data = parts[1]
                
                if seq and data:
                    try:
                        # Extract character from byte 8 (position 16 in hex)
                        if len(data) >= 18:  # Need at least 9 bytes (18 hex chars)
                            char_hex = data[16:18]  # Byte 8 in hex
                            char = bytes.fromhex(char_hex).decode('utf-8')
                            
                            if seq not in sequence_numbers:
                                captured_chars.append(char)
                                sequence_numbers.append(seq)
                    except:
                        pass
    
    return ''.join(captured_chars)

def extract_with_scapy(pcap_file):
    """Extract characters using scapy"""
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap(pcap_file)
        captured_chars = []
        sequence_numbers = []
        
        for packet in packets:
            if packet.haslayer('ICMP') and packet['ICMP'].type == 8:
                if packet.haslayer('Raw'):
                    data = packet['Raw'].load
                    
                    if len(data) >= 9:
                        # Extract character from byte 8
                        char = chr(data[8])
                        seq = packet['ICMP'].seq
                        
                        if seq not in sequence_numbers:
                            captured_chars.append(char)
                            sequence_numbers.append(seq)
        
        return ''.join(captured_chars)
        
    except ImportError:
        print("Scapy no disponible")
        return None
    except Exception as e:
        print(f"Error con scapy: {e}")
        return None

def decrypt_caesar(text, shift):
    """Decrypt text using Caesar cipher"""
    shift = shift % 26
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(ch)  # espacios, signos, etc. se conservan
    return ''.join(result)

def calculate_probability(text):
    """Calculate probability that text is a valid message"""
    # Common Spanish words
    spanish_words = ['y', 'en', 'de', 'la', 'el', 'un', 'una', 'con', 'por', 'para', 'que', 'como', 'muy', 'mas', 'pero', 'si', 'no', 'es', 'son', 'estan', 'tiene', 'puede', 'hacer', 'ver', 'dar', 'ir', 'ser', 'estar', 'tener', 'hacer', 'poder', 'decir', 'ver', 'dar', 'ir', 'llegar', 'pasar', 'quedar', 'poner', 'parecer', 'haber', 'saber', 'llegar', 'deber', 'querer', 'llegar', 'poder', 'deber', 'querer', 'llegar', 'poder', 'deber', 'querer']
    
    # Common words in the expected message
    expected_words = ['criptografia', 'seguridad', 'redes']
    
    score = 0
    text_lower = text.lower()
    
    # Check for Spanish words
    for word in spanish_words:
        if word in text_lower:
            score += 1
    
    # Check for expected words (higher weight)
    for word in expected_words:
        if word in text_lower:
            score += 5
    
    # Check for reasonable character distribution
    if text.count(' ') > 0:  # Has spaces
        score += 2
    
    if len(text) > 10:  # Reasonable length
        score += 1
    
    return score

if __name__ == "__main__":
    main()
