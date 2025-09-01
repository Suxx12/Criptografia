#!/usr/bin/env python3
import sys
import socket
import struct
import time
import random

def calculate_checksum(data):
    """Calculate ICMP checksum correctly"""
    if len(data) % 2 == 1:
        data += b'\x00'
    
    sum = 0
    for i in range(0, len(data), 2):
        sum += (data[i] << 8) + data[i + 1]
    
    while sum >> 16:
        sum = (sum & 0xFFFF) + (sum >> 16)
    
    return ~sum & 0xFFFF

def create_icmp_packet(icmp_type, icmp_code, identifier, sequence, data):
    """Create ICMP packet with proper data structure like real Windows ping"""
    # Create data payload exactly like real Windows ping (32 bytes total)
    # First 8 bytes: timestamp and sequence info (like real ping)
    timestamp = int(time.time() * 1000) & 0xFFFFFFFF
    data_header = struct.pack('!II', timestamp, sequence)
    
    # Add the character we want to send
    char_data = data
    
    # Fill remaining bytes with sequential pattern (like real Windows ping)
    remaining_bytes = 32 - len(data_header) - len(char_data)
    sequential_data = bytes([i for i in range(16, 16 + remaining_bytes)])
    
    # Combine all data
    full_data = data_header + char_data + sequential_data
    
    # ICMP header: type, code, checksum, identifier, sequence
    header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, identifier, sequence)
    
    # Calculate checksum correctly
    packet = header + full_data
    checksum_val = calculate_checksum(packet)
    
    # Rebuild header with correct checksum (no need for htons)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_val, identifier, sequence)
    
    return header + full_data

def send_icmp_packet(dest_ip, packet, timeout=1):
    """Send ICMP packet to destination"""
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        
        # Send packet
        sock.sendto(packet, (dest_ip, 0))
        print(f"Sent 1 packets.")
        
        sock.close()
        return True
    except Exception as e:
        print(f"Error sending packet: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 pingv4.py <texto_cifrado>")
        print("Ejemplo: python3 pingv4.py \"larycxpajorj h bnpdarmjm nw anmnb\"")
        sys.exit(1)
    
    # Get the encrypted text from command line arguments
    encrypted_text = ' '.join(sys.argv[1:])
    
    # Google's IP address (8.8.8.8)
    dest_ip = "8.8.8.8"
    
    print(f"Enviando caracteres cifrados a {dest_ip}...")
    print(f"Texto: {encrypted_text}")
    print(f"Total de caracteres: {len(encrypted_text)}")
    print("-" * 50)
    
    # Use consistent identifier like real Windows ping (0x0001)
    identifier = 0x0001
    
    # Send each character in a separate ICMP packet
    for i, char in enumerate(encrypted_text):
        # Use sequential numbering like real Windows ping
        sequence = i + 1
        
        # Convert character to bytes for ICMP data field
        data = char.encode('utf-8')
        
        # Create ICMP packet (type 8 = echo request)
        packet = create_icmp_packet(8, 0, identifier, sequence, data)
        
        # Send the packet
        success = send_icmp_packet(dest_ip, packet)
        
        if success:
            print(f"Carácter '{char}' enviado en paquete {sequence}")
        else:
            print(f"Error enviando carácter '{char}'")
        
        # Windows ping default timing: 1 second between packets
        time.sleep(1)
    
    print("-" * 50)
    print("Transmisión completada.")
if __name__ == "__main__":
    main()
