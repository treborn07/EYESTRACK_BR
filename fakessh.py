#!/usr/bin/env python3
import socket
import threading
import paramiko
from paramiko import RSAKey
import os

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        print(f"[+] Tentativa de login: {username}:{password}")
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        print(f"[+] Tentativa de chave pública: {username}")
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return "password,publickey"

class FakeSSHServer:
    def __init__(self, host='127.0.0.1', port=22):
        self.host = host
        self.port = port
        self.running = False
        
        # Gerar chave RSA temporária
        self.host_key = RSAKey.generate(2048)
    
    def handle_connection(self, client_socket):
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server = FakeSSHServer()
            transport.start_server(server=server)
            
            # Aceitar a conexão
            channel = transport.accept(20)
            if channel is None:
                transport.close()
                return
                
            # Fechar após breve espera
            transport.close()
            
        except Exception as e:
            print(f"Erro SSH: {e}")
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        self.running = True
        print(f"[+] Servidor SSH fake rodando em {self.host}:{self.port}")
        
        try:
            while self.running:
                client, addr = server_socket.accept()
                print(f"[+] Conexão SSH de {addr[0]}:{addr[1]}")
                
                client_handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client,)
                )
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\n[!] Servidor SSH parado pelo usuário")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = FakeSSHServer()
    server.start()
