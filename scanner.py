#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner de ports TCP en ligne de commande
Développé pour explorer les bases de la sécurité réseau
"""

import socket
from datetime import datetime
import sys
import threading
import platform
import os
import re
import subprocess
import time
    
def get_host_info(target):
    """
    Tente de récupérer des informations sur l'hôte cible
    """
    info = {}
    
    # Essayer de résoudre le nom d'hôte
    try:
        info['hostname'] = socket.gethostbyaddr(target)[0]
    except:
        info['hostname'] = "<Non résolu>"
    
    # Tenter de déterminer si l'hôte est joignable par ping
    ping_param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    ping_cmd = f"ping {ping_param} {target}"
    try:
        ping_output = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)
        info['ping'] = ping_output.returncode == 0
        
        # Extraire le TTL pour estimer le système d'exploitation
        if info['ping']:
            ttl_match = re.search(r"TTL=(\d+)", ping_output.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    info['os_guess'] = "Linux/Unix (TTL ≤ 64)"
                elif ttl <= 128:
                    info['os_guess'] = "Windows (TTL ≤ 128)"
                else:
                    info['os_guess'] = "Inconnu"
    except:
        info['ping'] = False
    
    return info

def scan_ports(target, start_port, end_port, timeout):
    open_ports = 0
    open_ports_list = []
    total_ports = end_port - start_port + 1
    start_time = datetime.now()
    
    print(f"\n=== Scanner de Ports TCP ===\n")
    print(f"Démarrage du scan: {start_time.strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"Cible: {target}")
    print(f"Ports: {start_port} à {end_port}")
    print(f"Timeout: {timeout} secondes")
    
    # Récupérer des informations sur l'hôte
    print("\nRécupération des informations sur l'hôte...")
    host_info = get_host_info(target)
    print(f"Nom d'hôte: {host_info.get('hostname', '<Non résolu>')}")
    print(f"Répond au ping: {'Oui' if host_info.get('ping', False) else 'Non'}")
    if 'os_guess' in host_info:
        print(f"Système d'exploitation probable: {host_info['os_guess']}")
    
    print(f"\nScan des ports en cours...")
    
    for i, port in enumerate(range(start_port, end_port + 1)):
        # Afficher la progression tous les 100 ports
        if i % 100 == 0:
            progress = (i / total_ports) * 100
            print(f"Progression: {int(progress)}% - Port actuel: {port}", end="\r")
            sys.stdout.flush()
        
        # Scanner le port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            open_ports += 1
            open_ports_list.append(port)
            service = get_service_name(port)
            # Essayer de récupérer la bannière du service
            banner = get_service_banner(target, port)
            if banner:
                print(f"Port {port} est ouvert - {service} - Bannière: {banner}")
            else:
                print(f"Port {port} est ouvert - {service}")
        s.close()
    
    end_time = datetime.now()
    time_taken = end_time - start_time
    
    # Afficher le résumé
    print(f"\n=== Résultat du scan ===\n")
    print(f"Scan terminé en {time_taken}")
    print(f"Ports ouverts: {open_ports}/{total_ports}")
    
    if open_ports > 0:
        print("\nRécapitulatif des ports ouverts:")
        for port in open_ports_list:
            print(f"  - {port}/tcp - {get_service_name(port)}")
    
    print(f"\nCible: {target} ({host_info.get('hostname', '<Non résolu>')})")
    if 'os_guess' in host_info:
        print(f"Système d'exploitation probable: {host_info['os_guess']}")
    
    print("\nScan réalisé avec le Mini Scanner de Ports TCP")
    print("Développé pour explorer les bases de la sécurité réseau")
    
def get_service_name(port):
    common_ports = {
        20: "FTP (données)",
        21: "FTP (contrôle)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MS SQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        9000: "PHP-FPM",
        9090: "Cockpit",
        9200: "Elasticsearch",
        27017: "MongoDB"
    }
    return common_ports.get(port, "Service inconnu")

def get_service_banner(ip, port, timeout=1):
    """
    Tente de récupérer la bannière du service sur le port spécifié
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Envoyer une requête HTTP pour les ports web courants
        if port in [80, 443, 8080, 8443]:
            s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        # Sinon, juste attendre la bannière
        
        banner = s.recv(1024)
        s.close()
        
        # Convertir en string et nettoyer
        try:
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            # Limiter à la première ligne
            banner_str = banner_str.split('\n')[0]
            # Limiter la longueur
            if len(banner_str) > 50:
                banner_str = banner_str[:50] + "..."
            return banner_str
        except:
            return "<Données binaires>" 
    except:
        return ""

def is_valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

if __name__ == "__main__":
    # Vérifier les arguments
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <ip> [start_port] [end_port] [timeout]")
        print("Exemple: python3 scanner.py 192.168.1.1 1 1024 0.5")
        sys.exit(1)
    
    # Récupérer les arguments
    target = sys.argv[1]
    
    # Valider l'adresse IP
    if not is_valid_ip(target):
        print(f"Erreur: '{target}' n'est pas une adresse IP valide.")
        print("Exemple d'adresse IP valide: 192.168.1.1")
        sys.exit(1)
    
    # Récupérer les autres arguments avec des valeurs par défaut
    try:
        start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
        timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
        
        if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
        
        if timeout <= 0:
            raise ValueError
    except ValueError:
        print("Erreur: Les ports doivent être des nombres entre 1 et 65535.")
        print("Le port de début doit être inférieur au port de fin.")
        print("Le timeout doit être un nombre positif.")
        sys.exit(1)
    
    # Lancer le scan
    scan_ports(target, start_port, end_port, timeout)
