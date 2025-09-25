#!/usr/bin/env python3
import socket
import threading

class FakeFTPServer:
    def __init__(self, host='127.0.0.1', port=2121):
        self.host = host
        self.port = port
        self.running = False
        self.current_user = None
        
        # 👇 AQUI VOCÊ CONFIGURA OS USUÁRIOS E SENHAS 👇
        self.valid_users = {
            "admin": "admin123",
            "root": "toor", 
            "teste": "senha123",
            "ftpuser": "ftppass",
            "mint": "linuxmint",
            "user": "password"
        }

    def handle_client(self, client_socket, addr):
        try:
            client_socket.send(b"220 Welcome to Fake FTP Server\r\n")
            print(f"[+] Conexão de {addr[0]}:{addr[1]}")
            
            while True:
                data = client_socket.recv(1024).decode().strip()
                if not data:
                    break
                    
                print(f"FTP - Comando: {data}")
                
                if data.upper().startswith("USER"):
                    username = data.split()[1] if len(data.split()) > 1 else ""
                    self.current_user = username
                    client_socket.send(b"331 User name okay, need password\r\n")
                    
                elif data.upper().startswith("PASS"):
                    password = data.split()[1] if len(data.split()) > 1 else ""
                    
                    if self.current_user in self.valid_users and self.valid_users[self.current_user] == password:
                        client_socket.send(b"230 User logged in successfully\r\n")
                        print(f"[+] Login bem-sucedido: {self.current_user}:{password}")
                    else:
                        client_socket.send(b"530 Login incorrect\r\n")
                        print(f"[!] Login falhou: {self.current_user}:{password}")
                        
                elif data.upper().startswith("QUIT"):
                    client_socket.send(b"221 Goodbye!\r\n")
                    break
                else:
                    client_socket.send(b"200 OK\r\n")
                    
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
        print(f"[+] Servidor FTP rodando em {self.host}:{self.port}")
        print("[+] Usuários configurados:")
        for user, password in self.valid_users.items():
            print(f"    {user}:{password}")
        print("[+] Teste com: hydra -l admin -P wordlist.txt ftp://127.0.0.1:2121")
        
        try:
            while self.running:
                client, addr = server.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\n[!] Servidor parado")
        finally:
            server.close()

if __name__ == "__main__":
    server = FakeFTPServer(port=2121)
    server.start()
