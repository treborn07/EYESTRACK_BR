#!/usr/bin/env python3
import socket
import threading
import os

class FakeFTPServer:
    def __init__(self, host='127.0.0.1', port=21):
        self.host = host
        self.port = port
        self.running = False
        
    def handle_client(self, client_socket):
        client_socket.send(b"220 Welcome to Fake FTP Server\r\n")
        
        try:
            while True:
                data = client_socket.recv(1024).decode().strip()
                if not data:
                    break
                    
                print(f"Comando recebido: {data}")
                
                if data.upper().startswith("USER"):
                    client_socket.send(b"331 User name okay, need password\r\n")
                elif data.upper().startswith("PASS"):
                    client_socket.send(b"230 User logged in successfully\r\n")
                elif data.upper().startswith("QUIT"):
                    client_socket.send(b"221 Goodbye!\r\n")
                    break
                elif data.upper().startswith("SYST"):
                    client_socket.send(b"215 UNIX Type: L8\r\n")
                elif data.upper().startswith("FEAT"):
                    client_socket.send(b"211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n211 End\r\n")
                else:
                    client_socket.send(b"500 Command not understood\r\n")
                    
        except Exception as e:
            print(f"Erro: {e}")
        finally:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        self.running = True
        print(f"[+] Servidor FTP fake rodando em {self.host}:{self.port}")
        
        try:
            while self.running:
                client, addr = server.accept()
                print(f"[+] Conexão de {addr[0]}:{addr[1]}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client,)
                )
                client_handler.start()
        except KeyboardInterrupt:
            print("\n[!] Servidor parado pelo usuário")
        finally:
            server.close()

if __name__ == "__main__":
    server = FakeFTPServer()
    server.start()
