import socket
import threading
import time
import json
import base64
from cryptography.hazmat.primitives import serialization
from crypto_protocol import CryptoProtocol


class Trent:
    """Trusted Third Party - доверенный центр распределения ключей"""
    
    def __init__(self, port=9999, host='localhost'):
        self.port = port
        self.host = host
        self.server_socket = None
        self.crypto = CryptoProtocol()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.active = True
        self.sessions = {}
        self.users = {}
        
    def start(self):
        """Запускает сервер Трента"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[Трент] Запущен на {self.host}:{self.port}")
        print(f"[Трент] Ожидание регистрации участников...\n")
        
        thread = threading.Thread(target=self._accept_connections, daemon=True)
        thread.start()
        
        print("[Трент] Запустите alice.py и bob.py в других терминалах\n")
        
        try:
            while self.active:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        
    def _accept_connections(self):
        """Принимает соединения от Алисы и Боба"""
        while self.active:
            try:
                self.server_socket.settimeout(1)
                client_socket, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except:
                break
    
    def _handle_client(self, client_socket, addr):
        """Обрабатывает запрос от клиента"""
        try:
            data = client_socket.recv(4096)
            if not data:
                return
            
            message = json.loads(data.decode())
            
            if message.get('type') == 'register':
                self._handle_registration(client_socket, message)
            elif message.get('type') == 'setup_request':
                self._handle_setup_request(client_socket, message)
            
            client_socket.close()
        except Exception as e:
            print(f"[Трент] Ошибка: {e}")
            client_socket.close()
    
    def _handle_registration(self, client_socket, message):
        """Регистрирует публичный ключ пользователя"""
        try:
            user_id = message.get('user_id')
            public_key_bytes = base64.b64decode(message.get('public_key'))
            host = message.get('host', 'localhost')
            port = message.get('port', 0)
            
            public_key = serialization.load_pem_public_key(
                public_key_bytes, backend=self.crypto.backend
            )
            
            self.users[user_id] = {
                'public_key': public_key,
                'host': host,
                'port': port
            }
            print(f"[Трент] Зарегистрирован пользователь: {user_id} ({host}:{port})")
            
            response = {'type': 'register_response', 'status': 'ok'}
            client_socket.sendall(json.dumps(response).encode())
        except Exception as e:
            print(f"[Трент] Ошибка регистрации: {e}")
            response = {'type': 'register_response', 'status': 'error', 'message': str(e)}
            client_socket.sendall(json.dumps(response).encode())
    
    def _handle_setup_request(self, client_socket, message):
        """Обрабатывает запрос на установку сессии"""
        try:
            alice_id = message.get('alice_id')
            bob_id = message.get('bob_id')
            
            if alice_id not in self.users:
                raise Exception(f"Пользователь {alice_id} не зарегистрирован")
            if bob_id not in self.users:
                raise Exception(f"Пользователь {bob_id} не зарегистрирован")
            
            alice_public_key = self.users[alice_id]['public_key']
            bob_public_key = self.users[bob_id]['public_key']
            alice_host = self.users[alice_id]['host']
            alice_port = self.users[alice_id]['port']
            bob_host = self.users[bob_id]['host']
            bob_port = self.users[bob_id]['port']
            
            print(f"[Трент] Получен запрос: {alice_id} -> {bob_id}")
            
            response = self._process_setup_request(
                alice_id, bob_id, alice_public_key, bob_public_key,
                alice_host, alice_port, bob_host, bob_port
            )
            
            print(f"[Трент] Генерирован сессионный ключ и отправлен ответ {alice_id}")
            client_socket.sendall(json.dumps(response).encode())
        except Exception as e:
            print(f"[Трент] Ошибка установки: {e}")
            response = {'type': 'setup_response', 'status': 'error', 'message': str(e)}
            client_socket.sendall(json.dumps(response).encode())
    
    def _process_setup_request(self, alice_id, bob_id, alice_public_key, bob_public_key, alice_host, alice_port, bob_host, bob_port):
        """Шаг 2: Трент генерирует ответ для Алисы"""
        timestamp = int(time.time())
        lifetime = 60
        session_key = self.crypto.generate_session_key()
        
        message_for_alice = json.dumps({
            'timestamp': timestamp,
            'lifetime': lifetime,
            'session_key': base64.b64encode(session_key).decode(),
            'bob_id': bob_id,
            'bob_host': bob_host,
            'bob_port': bob_port
        }).encode()
        
        message_for_bob = json.dumps({
            'timestamp': timestamp,
            'lifetime': lifetime,
            'session_key': base64.b64encode(session_key).decode(),
            'alice_id': alice_id,
            'alice_host': alice_host,
            'alice_port': alice_port
        }).encode()
        
        encrypted_for_alice = self.crypto.encrypt_rsa(alice_public_key, message_for_alice)
        encrypted_for_bob = self.crypto.encrypt_rsa(bob_public_key, message_for_bob)
        
        session_key_hash = base64.b64encode(session_key).decode()
        self.sessions[session_key_hash] = {
            'alice_id': alice_id,
            'bob_id': bob_id,
            'timestamp': timestamp,
            'lifetime': lifetime
        }
        
        return {
            'type': 'setup_response',
            'encrypted_for_alice': base64.b64encode(encrypted_for_alice).decode(),
            'encrypted_for_bob': base64.b64encode(encrypted_for_bob).decode(),
            'session_id': session_key_hash
        }
    
    def stop(self):
        """Останавливает сервер"""
        print("\n[Трент] Завершение работы...")
        self.active = False
        if self.server_socket:
            self.server_socket.close()


if __name__ == '__main__':
    trent = Trent(port=9999, host = "localhost")
    trent.start()
