#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# EyeTrack Security Toolkit - Canivete Suíço de Segurança
# Versão 3.0 - Com integração de serviços
# Autor: Assistente AI
# Licença: MIT

import os
import sys
import base64
import hashlib
import socket
import threading
import subprocess
import random
import string
import webbrowser
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
    {Colors.BOLD}{Colors.PURPLE}EYETRACK SECURITY TOOLKIT{Colors.RESET} {Colors.CYAN}v3.0{Colors.RESET}
    {Colors.YELLOW}Para fins educacionais e éticos{Colors.RESET}
    
    {Colors.GREEN}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣷⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⡿⠟⠛⠛⠛⠛⠻⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣁⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⠛⠉⠛⠶⠀⠀⢐⠿⠋⠀⢨⣿⣿⣿⣿⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⢷⣿⣿⣶⠀⠀⠉⢶⣿⣿⠿⢿⣿⣿⣿⡄⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢸⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⡇⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣶⡶⠂⠀⣀⠀⢀⡄⠐⢲⡾⣻⣿⣿⣿⠇⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣯⢿⡶⣶⣿⣟⣿⡶⠶⣿⢣⣿⣿⣿⣿⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⣀⣾⣿⣿⣿⣿⣧⠛⠒⠠⣤⣤⠶⠾⢣⣿⣿⣿⣿⣤⣀⠀⠀⠀
    ⢀⣠⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⢿⣿⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{Colors.RESET}
    """
    print(banner)

def advanced_encrypt(text, key):
    """Criptografia avançada usando AES simulado com padding PKCS7"""
    # Deriva uma chave de 32 bytes da chave fornecida
    key_hash = hashlib.sha256(key.encode()).digest()
    
    # Converte o texto para bytes
    text_bytes = text.encode('utf-8')
    
    # Adiciona padding PKCS7
    block_size = 16
    padding_length = block_size - (len(text_bytes) % block_size)
    padding = bytes([padding_length] * padding_length)
    padded_text = text_bytes + padding
    
    # Criptografia simples XOR com a chave (simulando AES)
    encrypted = bytearray()
    for i in range(len(padded_text)):
        key_byte = key_hash[i % len(key_hash)]
        encrypted_byte = padded_text[i] ^ key_byte
        encrypted.append(encrypted_byte)
    
    # Codifica em base64 para fácil armazenamento
    return base64.urlsafe_b64encode(bytes(encrypted)).decode()

def advanced_decrypt(encrypted_text, key):
    """Descriptografia avançada"""
    try:
        # Deriva a chave
        key_hash = hashlib.sha256(key.encode()).digest()
        
        # Decodifica do base64
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
        
        # Descriptografia XOR
        decrypted = bytearray()
        for i in range(len(encrypted_bytes)):
            key_byte = key_hash[i % len(key_hash)]
            decrypted_byte = encrypted_bytes[i] ^ key_byte
            decrypted.append(decrypted_byte)
        
        # Remove padding PKCS7
        padding_length = decrypted[-1]
        if padding_length > 0 and padding_length <= 16:
            decrypted = decrypted[:-padding_length]
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return None

def encrypt_text():
    """Criptografa texto com chave específica"""
    text = input(f"{Colors.YELLOW}[?] Digite o texto para criptografar: {Colors.RESET}")
    key = input(f"{Colors.YELLOW}[?] Digite a chave de criptografia: {Colors.RESET}")
    
    if not text or not key:
        print(f"{Colors.RED}[-] Texto e chave são obrigatórios!{Colors.RESET}")
        return
    
    encrypted = advanced_encrypt(text, key)
    print(f"{Colors.GREEN}[+] Texto criptografado:{Colors.RESET}")
    print(f"{Colors.CYAN}{encrypted}{Colors.RESET}")
    
    # Oferece opção para salvar em arquivo
    save = input(f"{Colors.YELLOW}[?] Salvar em arquivo? (s/n): {Colors.RESET}").lower()
    if save == 's':
        filename = input(f"{Colors.YELLOW}[?] Nome do arquivo: {Colors.RESET}")
        try:
            with open(filename, 'w') as f:
                f.write(encrypted)
            print(f"{Colors.GREEN}[+] Texto salvo em: {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Erro ao salvar arquivo: {e}{Colors.RESET}")

def decrypt_text():
    """Descriptografa texto com chave específica"""
    encrypted_text = input(f"{Colors.YELLOW}[?] Digite o texto criptografado: {Colors.RESET}")
    key = input(f"{Colors.YELLOW}[?] Digite a chave de descriptografia: {Colors.RESET}")
    
    if not encrypted_text or not key:
        print(f"{Colors.RED}[-] Texto criptografado e chave são obrigatórios!{Colors.RESET}")
        return
    
    decrypted = advanced_decrypt(encrypted_text, key)
    
    if decrypted is None:
        print(f"{Colors.RED}[-] Falha na descriptografia - chave incorreta ou texto inválido!{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] Texto descriptografado:{Colors.RESET}")
        print(f"{Colors.CYAN}{decrypted}{Colors.RESET}")

def simple_encrypt(text, key):
    """Criptografia simples usando XOR (compatível com Termux)"""
    encrypted = []
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        encrypted.append(encrypted_char)
    return base64.urlsafe_b64encode(''.join(encrypted).encode()).decode()

def simple_decrypt(encrypted_text, key):
    """Descriptografia simples usando XOR (compatível com Termux)"""
    try:
        decoded = base64.urlsafe_b64decode(encrypted_text).decode()
        decrypted = []
        for i, char in enumerate(decoded):
            key_char = key[i % len(key)]
            decrypted_char = chr(ord(char) ^ ord(key_char))
            decrypted.append(decrypted_char)
        return ''.join(decrypted)
    except:
        return None

def encrypt_file(filename, key):
    """Criptografa um arquivo usando criptografia simples"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            file_data = file.read()
        
        encrypted_data = simple_encrypt(file_data, key)
        
        with open(filename + '.encrypted', 'w') as file:
            file.write(encrypted_data)
        
        print(f"{Colors.GREEN}[+] Arquivo criptografado com sucesso: {filename}.encrypted{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao criptografar: {str(e)}{Colors.RESET}")
        return False

def decrypt_file(filename, key):
    """Descriptografa um arquivo usando criptografia simples"""
    try:
        with open(filename, 'r') as file:
            encrypted_data = file.read()
        
        decrypted_data = simple_decrypt(encrypted_data, key)
        
        if decrypted_data is None:
            print(f"{Colors.RED}[-] Falha na descriptografia - chave incorreta?{Colors.RESET}")
            return False
        
        output_filename = filename.replace('.encrypted', '.decrypted')
        with open(output_filename, 'w', encoding='utf-8') as file:
            file.write(decrypted_data)
        
        print(f"{Colors.GREEN}[+] Arquivo descriptografado com sucesso: {output_filename}{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao descriptografar: {str(e)}{Colors.RESET}")
        return False

def hash_file(filename, algorithm='sha256'):
    """Calcula o hash de um arquivo"""
    try:
        hash_func = hashlib.new(algorithm)
        with open(filename, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_func.update(chunk)
        
        print(f"{Colors.GREEN}[+] Hash {algorithm.upper()} do arquivo: {hash_func.hexdigest()}{Colors.RESET}")
        return hash_func.hexdigest()
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao calcular hash: {str(e)}{Colors.RESET}")
        return None

def port_scan(target, ports):
    """Escaneia portas em um alvo"""
    print(f"{Colors.BLUE}[*] Iniciando varredura de portas em {target}{Colors.RESET}")
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                print(f"{Colors.GREEN}[+] Porta {port} aberta{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Porta {port} fechada{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro no scan de portas: {str(e)}{Colors.RESET}")

def generate_password(length=12):
    """Gera uma senha forte"""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    print(f"{Colors.GREEN}[+] Senha gerada: {password}{Colors.RESET}")
    return password

def network_info():
    """Exibe informações de rede"""
    try:
        # Obtém o nome do host
        hostname = socket.gethostname()
        print(f"{Colors.BLUE}[*] Nome do host: {hostname}{Colors.RESET}")
        
        # Obtém o endereço IP
        ip = socket.gethostbyname(hostname)
        print(f"{Colors.BLUE}[*] Endereço IP: {ip}{Colors.RESET}")
        
        # Obtém interfaces de rede (Linux/Unix)
        if os.name != 'nt':
            try:
                # Tenta usar ip command (mais moderno)
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{Colors.BLUE}[*] Interfaces de rede:{Colors.RESET}")
                    print(result.stdout)
                else:
                    # Fallback para ifconfig
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    print(f"{Colors.BLUE}[*] Interfaces de rede:{Colors.RESET}")
                    print(result.stdout)
            except:
                print(f"{Colors.YELLOW}[*] Comandos de rede não disponíveis{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao obter informações de rede: {str(e)}{Colors.RESET}")

def directory_listing(path="."):
    """Lista arquivos e diretórios com informações"""
    try:
        print(f"{Colors.BLUE}[*] Listando conteúdo de: {path}{Colors.RESET}")
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                print(f"{Colors.BLUE}[DIR]  {item}{Colors.RESET}")
            else:
                size = os.path.getsize(item_path)
                print(f"{Colors.GREEN}[FILE] {item} ({size} bytes){Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao listar diretório: {str(e)}{Colors.RESET}")

def file_info(filename):
    """Exibe informações sobre um arquivo"""
    try:
        if not os.path.exists(filename):
            print(f"{Colors.RED}[-] Arquivo não encontrado{Colors.RESET}")
            return
        
        stats = os.stat(filename)
        print(f"{Colors.BLUE}[*] Informações do arquivo: {filename}{Colors.RESET}")
        print(f"{Colors.CYAN}    Tamanho: {stats.st_size} bytes{Colors.RESET}")
        print(f"{Colors.CYAN}    Modificado: {datetime.fromtimestamp(stats.st_mtime)}{Colors.RESET}")
        print(f"{Colors.CYAN}    Permissões: {oct(stats.st_mode)[-3:]}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao obter informações do arquivo: {str(e)}{Colors.RESET}")

def run_eyeslab():
    """Executa o programa eyeslab.py"""
    try:
        eyeslab_file = "eyeslab.py"
        if os.path.exists(eyeslab_file):
            print(f"{Colors.BLUE}[*] Executando eyeslab.py...{Colors.RESET}")
            os.system(f"python {eyeslab_file}")
            print(f"{Colors.GREEN}[+] eyeslab.py executado com sucesso{Colors.RESET}")
        else:
            print(f"{Colors.RED}[-] Arquivo não encontrado: {eyeslab_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao executar eyeslab.py: {str(e)}{Colors.RESET}")

def run_fake_ftp():
    """Executa o servidor FTP fake"""
    try:
        fakeftp_file = "fakeftp.py"
        if os.path.exists(fakeftp_file):
            print(f"{Colors.BLUE}[*] Iniciando servidor FTP fake...{Colors.RESET}")
            # Executa em uma thread separada para não bloquear o menu
            thread = threading.Thread(target=lambda: os.system(f"python {fakeftp_file}"))
            thread.daemon = True
            thread.start()
            print(f"{Colors.GREEN}[+] Servidor FTP fake iniciado em segundo plano{Colors.RESET}")
        else:
            print(f"{Colors.RED}[-] Arquivo não encontrado: {fakeftp_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao iniciar servidor FTP fake: {str(e)}{Colors.RESET}")

def run_fake_ssh():
    """Executa o servidor SSH fake"""
    try:
        fakessh_file = "fakessh.py"
        if os.path.exists(fakessh_file):
            print(f"{Colors.BLUE}[*] Iniciando servidor SSH fake...{Colors.RESET}")
            # Executa em uma thread separada para não bloquear o menu
            thread = threading.Thread(target=lambda: os.system(f"python {fakessh_file}"))
            thread.daemon = True
            thread.start()
            print(f"{Colors.GREEN}[+] Servidor SSH fake iniciado em segundo plano{Colors.RESET}")
        else:
            print(f"{Colors.RED}[-] Arquivo não encontrado: {fakessh_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao iniciar servidor SSH fake: {str(e)}{Colors.RESET}")

def run_termux_ftp():
    """Executa o servidor FTP para Termux"""
    try:
        termuxftp_file = "termuxftpfake.py"
        if os.path.exists(termuxftp_file):
            print(f"{Colors.BLUE}[*] Iniciando servidor FTP para Termux...{Colors.RESET}")
            # Executa em uma thread separada para não bloquear o menu
            thread = threading.Thread(target=lambda: os.system(f"python {termuxftp_file}"))
            thread.daemon = True
            thread.start()
            print(f"{Colors.GREEN}[+] Servidor FTP para Termux iniciado em segundo plano{Colors.RESET}")
        else:
            print(f"{Colors.RED}[-] Arquivo não encontrado: {termuxftp_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Erro ao iniciar servidor FTP para Termux: {str(e)}{Colors.RESET}")

def list_available_tools():
    """Lista as ferramentas disponíveis no diretório"""
    print(f"{Colors.BOLD}{Colors.WHITE}Ferramentas disponíveis:{Colors.RESET}")
    
    tools = [
        ("eyeslab.py", "Laboratório Flask", run_eyeslab),
        ("fakeftp.py", "Servidor FTP fake", run_fake_ftp),
        ("fakessh.py", "Servidor SSH fake", run_fake_ssh),
        ("termuxftpfake.py", "Servidor FTP Termux", run_termux_ftp)
    ]
    
    for i, (filename, description, _) in enumerate(tools, 1):
        if os.path.exists(filename):
            status = f"{Colors.GREEN}[Disponível]{Colors.RESET}"
        else:
            status = f"{Colors.RED}[Não encontrado]{Colors.RESET}"
        print(f"{Colors.CYAN}[{i}] {description} {status}{Colors.RESET}")

def main():
    clear_screen()
    print_banner()
    
    while True:
        print(f"\n{Colors.BOLD}{Colors.WHITE}Menu Principal:{Colors.RESET}")
        print(f"{Colors.CYAN}[1] Ferramentas de Segurança{Colors.RESET}")
        print(f"{Colors.CYAN}[2] Ferramentas do EyeTrack{Colors.RESET}")
        print(f"{Colors.CYAN}[3] Servidores e Laboratórios{Colors.RESET}")
        print(f"{Colors.RED}[0] Sair{Colors.RESET}")
        
        choice = input(f"\n{Colors.YELLOW}[?] Selecione uma opção: {Colors.RESET}")
        
        if choice == '1':
            # Submenu de ferramentas de segurança
            while True:
                print(f"\n{Colors.BOLD}{Colors.WHITE}Ferramentas de Segurança:{Colors.RESET}")
                print(f"{Colors.CYAN}[1] Criptografar texto{Colors.RESET}")
                print(f"{Colors.CYAN}[2] Descriptografar texto{Colors.RESET}")
                print(f"{Colors.CYAN}[3] Criptografar arquivo{Colors.RESET}")
                print(f"{Colors.CYAN}[4] Descriptografar arquivo{Colors.RESET}")
                print(f"{Colors.CYAN}[5] Calcular hash de arquivo{Colors.RESET}")
                print(f"{Colors.CYAN}[6] Escanear portas{Colors.RESET}")
                print(f"{Colors.CYAN}[7] Gerar senha forte{Colors.RESET}")
                print(f"{Colors.CYAN}[8] Informações de rede{Colors.RESET}")
                print(f"{Colors.CYAN}[9] Listar diretório{Colors.RESET}")
                print(f"{Colors.CYAN}[10] Informações do arquivo{Colors.RESET}")
                print(f"{Colors.PURPLE}[11] Voltar ao menu principal{Colors.RESET}")
                
                sub_choice = input(f"\n{Colors.YELLOW}[?] Selecione uma opção: {Colors.RESET}")
                
                if sub_choice == '1':
                    encrypt_text()
                
                elif sub_choice == '2':
                    decrypt_text()
                
                elif sub_choice == '3':
                    filename = input(f"{Colors.YELLOW}[?] Caminho do arquivo para criptografar: {Colors.RESET}")
                    key = input(f"{Colors.YELLOW}[?] Digite uma chave para criptografia: {Colors.RESET}")
                    encrypt_file(filename, key)
                
                elif sub_choice == '4':
                    filename = input(f"{Colors.YELLOW}[?] Caminho do arquivo para descriptografar: {Colors.RESET}")
                    key = input(f"{Colors.YELLOW}[?] Digite a chave de descriptografia: {Colors.RESET}")
                    decrypt_file(filename, key)
                
                elif sub_choice == '5':
                    filename = input(f"{Colors.YELLOW}[?] Caminho do arquivo: {Colors.RESET}")
                    algorithm = input(f"{Colors.YELLOW}[?] Algoritmo (md5, sha1, sha256 - padrão): {Colors.RESET}") or 'sha256'
                    hash_file(filename, algorithm)
                
                elif sub_choice == '6':
                    target = input(f"{Colors.YELLOW}[?] Alvo (IP ou hostname): {Colors.RESET}")
                    port_range = input(f"{Colors.YELLOW}[?] Intervalo de portas (ex: 80,443 ou 1-100): {Colors.RESET}")
                    
                    if '-' in port_range:
                        start, end = map(int, port_range.split('-'))
                        ports = list(range(start, end + 1))
                    else:
                        ports = list(map(int, port_range.split(',')))
                    
                    port_scan(target, ports)
                
                elif sub_choice == '7':
                    length = input(f"{Colors.YELLOW}[?] Comprimento da senha (padrão: 12): {Colors.RESET}") or '12'
                    generate_password(int(length))
                
                elif sub_choice == '8':
                    network_info()
                
                elif sub_choice == '9':
                    path = input(f"{Colors.YELLOW}[?] Caminho do diretório (padrão: atual): {Colors.RESET}") or "."
                    directory_listing(path)
                
                elif sub_choice == '10':
                    filename = input(f"{Colors.YELLOW}[?] Caminho do arquivo: {Colors.RESET}")
                    file_info(filename)
                
                elif sub_choice == '11':
                    break
                
                else:
                    print(f"{Colors.RED}[-] Opção inválida!{Colors.RESET}")
                
                input(f"\n{Colors.YELLOW}[?] Pressione Enter para continuar...{Colors.RESET}")
                clear_screen()
                print_banner()
        
        elif choice == '2':
            # Submenu de ferramentas do EyeTrack
            while True:
                print(f"\n{Colors.BOLD}{Colors.WHITE}Ferramentas do EyeTrack:{Colors.RESET}")
                list_available_tools()
                print(f"{Colors.PURPLE}[5] Voltar ao menu principal{Colors.RESET}")
                
                sub_choice = input(f"\n{Colors.YELLOW}[?] Selecione uma opção: {Colors.RESET}")
                
                if sub_choice == '1':
                    run_eyeslab()
                elif sub_choice == '2':
                    run_fake_ftp()
                elif sub_choice == '3':
                    run_fake_ssh()
                elif sub_choice == '4':
                    run_termux_ftp()
                elif sub_choice == '5':
                    break
                else:
                    print(f"{Colors.RED}[-] Opção inválida!{Colors.RESET}")
                
                input(f"\n{Colors.YELLOW}[?] Pressione Enter para continuar...{Colors.RESET}")
                clear_screen()
                print_banner()
        
        elif choice == '3':
            # Submenu de servidores e laboratórios
            while True:
                print(f"\n{Colors.BOLD}{Colors.WHITE}Servidores e Laboratórios:{Colors.RESET}")
                print(f"{Colors.CYAN}[1] Iniciar servidor FTP fake{Colors.RESET}")
                print(f"{Colors.CYAN}[2] Iniciar servidor SSH fake{Colors.RESET}")
                print(f"{Colors.CYAN}[3] Iniciar servidor FTP Termux{Colors.RESET}")
                print(f"{Colors.CYAN}[4] Executar laboratório Flask{Colors.RESET}")
                print(f"{Colors.PURPLE}[5] Voltar ao menu principal{Colors.RESET}")
                
                sub_choice = input(f"\n{Colors.YELLOW}[?] Selecione uma opção: {Colors.RESET}")
                
                if sub_choice == '1':
                    run_fake_ftp()
                elif sub_choice == '2':
                    run_fake_ssh()
                elif sub_choice == '3':
                    run_termux_ftp()
                elif sub_choice == '4':
                    run_eyeslab()
                elif sub_choice == '5':
                    break
                else:
                    print(f"{Colors.RED}[-] Opção inválida!{Colors.RESET}")
                
                input(f"\n{Colors.YELLOW}[?] Pressione Enter para continuar...{Colors.RESET}")
                clear_screen()
                print_banner()
        
        elif choice == '0':
            print(f"{Colors.RED}[!] Saindo...{Colors.RESET}")
            break
        
        else:
            print(f"{Colors.RED}[-] Opção inválida!{Colors.RESET}")
        
        input(f"\n{Colors.YELLOW}[?] Pressione Enter para continuar...{Colors.RESET}")
        clear_screen()
        print_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrompido pelo usuário.{Colors.RESET}")
        sys.exit(0)
