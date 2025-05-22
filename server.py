#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Serveur web pour le scanner de ports TCP
"""

import http.server
import socketserver
import json
import subprocess
import os
import sys
import urllib.parse
from scanner import scan_ports, is_valid_ip

# Port pour le serveur web
PORT = 8888

class ScannerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Servir les fichiers statiques
        if self.path == '/' or self.path.startswith('/?'):
            self.path = '/index.html'
        
        # Essayer de servir le fichier demandé
        try:
            # Extraire le chemin de base sans les paramètres de requête
            base_path = self.path.split('?')[0]
            
            # Vérifier si le fichier existe
            file_path = os.path.join(os.getcwd(), base_path.lstrip('/'))
            
            if os.path.isfile(file_path):
                file_to_open = open(file_path, 'rb')
                self.send_response(200)
                
                # Définir le type MIME
                if base_path.endswith('.html'):
                    self.send_header('Content-type', 'text/html')
                elif base_path.endswith('.js'):
                    self.send_header('Content-type', 'application/javascript')
                elif base_path.endswith('.css'):
                    self.send_header('Content-type', 'text/css')
                else:
                    self.send_header('Content-type', 'application/octet-stream')
                
                self.end_headers()
                self.wfile.write(file_to_open.read())
                file_to_open.close()
                return
            else:
                self.send_error(404, f'Fichier non trouvé: {file_path}')
        except Exception as e:
            self.send_error(500, f'Erreur serveur: {str(e)}')
    
    def do_POST(self):
        # Traiter les requêtes POST pour le scan
        print(f"Requête POST reçue: {self.path}")
        
        if self.path == '/scan':
            # Lire les données de la requête
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            print(f"Données reçues: {post_data}")
            data = json.loads(post_data)
            
            # Récupérer les paramètres
            target = data.get('ip', '').strip()
            start_port = int(data.get('start_port', 1))
            end_port = int(data.get('end_port', 1024))
            timeout = float(data.get('timeout', 0.5))
            
            # Valider l'adresse IP
            if not is_valid_ip(target):
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'error': f"'{target}' n'est pas une adresse IP valide."}
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Valider les ports
            if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535 or start_port > end_port:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'error': 'Les ports doivent être des nombres entre 1 et 65535.'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Valider le timeout
            if timeout <= 0:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'error': 'Le timeout doit être un nombre positif.'}
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Exécuter la commande scanner.py
            try:
                cmd = [sys.executable, 'scanner.py', target, str(start_port), str(end_port), str(timeout)]
                print(f"Exécution de la commande: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                print(f"Résultat: code={result.returncode}, stdout={len(result.stdout)} caractères, stderr={len(result.stderr)} caractères")
                
                # Envoyer la réponse
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    'output': result.stdout,
                    'error': result.stderr,
                    'exit_code': result.returncode
                }
                self.wfile.write(json.dumps(response).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'error': str(e)}
                self.wfile.write(json.dumps(response).encode())

def run_server():
    # Créer le serveur
    handler = ScannerHandler
    httpd = socketserver.TCPServer(("", PORT), handler)
    
    print(f"Serveur démarré sur le port {PORT}")
    print(f"Ouvrez votre navigateur à l'adresse http://localhost:{PORT}")
    
    # Démarrer le serveur
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Serveur arrêté")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
