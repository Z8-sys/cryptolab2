import socket
import threading
import time
import json
import base64
from cryptography.hazmat.primitives import serialization
from crypto_protocol import CryptoProtocol


class Bob:
    """Участник Боб в протоколе"""
    
    def __init__(self, alice_id='Alice', bob_id='Bob', trent_host='localhost', trent_port=9999, bob_host='localhost', bob_port=10002):
        self.alice_id = alice_id
        self.bob_id = bob_id
        self.trent_host = trent_host
        self.trent_port = trent_port
        self.bob_host = bob_host
        self.bob_port = bob_port
        self.crypto = CryptoProtocol()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.session_key = None
        self.server_socket = None
        self.alice_host = None
        self.alice_port = None
        self.alice_id = None
        self.auth_received = False
        
    def get_public_key_bytes(self):
        """Получает публичный ключ в формате PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def register_at_trent(self):
        """Боб регистрирует свой публичный ключ у Трента"""
        print(f"[{self.bob_id}] Регистрация у Трента")
        
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.trent_host, self.trent_port))
            
            message = {
                'type': 'register',
                'user_id': self.bob_id,
                'public_key': base64.b64encode(self.get_public_key_bytes()).decode(),
                'host': self.bob_host,
                'port': self.bob_port
            }
            
            socket_client.sendall(json.dumps(message).encode())
            
            response_data = socket_client.recv(1024)
            response = json.loads(response_data.decode())
            socket_client.close()
            
            if response.get('status') == 'ok':
                print(f"[{self.bob_id}] Успешно зарегистрирован\n")
                return True
            else:
                print(f"[{self.bob_id}] Ошибка регистрации: {response.get('message')}")
                return False
        except Exception as e:
            print(f"[{self.bob_id}] Ошибка подключения к Тренту: {e}")
            return False
    
    def start_listening(self):
        """Запускает сервер для приема сообщений от Алисы"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.bob_host, self.bob_port))
        self.server_socket.listen(5)
        print(f"[{self.bob_id}] Слушает на {self.bob_host}:{self.bob_port}")
        print(f"[{self.bob_id}] Ожидание сообщения от Алисы...\n")
        
        thread = threading.Thread(target=self._accept_connections, daemon=True)
        thread.start()
    
    def _accept_connections(self):
        """Принимает соединения от Алисы (аутентификация и чат)"""
        self.auth_received = False
        while True:
            try:
                self.server_socket.settimeout(1)
                client_socket, addr = self.server_socket.accept()
                if not self.auth_received:
                    thread = threading.Thread(
                        target=self._handle_auth_message,
                        args=(client_socket,),
                        daemon=True
                    )
                    thread.start()
                else:
                    thread = threading.Thread(
                        target=self._handle_chat_message,
                        args=(client_socket,),
                        daemon=True
                    )
                    thread.start()
            except socket.timeout:
                continue
            except:
                break
    
    def _handle_auth_message(self, client_socket):
        """Обрабатывает аутентификационное сообщение от Алисы"""
        try:
            data = client_socket.recv(8192)
            if not data:
                return
            
            message = json.loads(data.decode())
            
            encrypted_for_bob = base64.b64decode(message['encrypted_for_bob'])
            encrypted_alice_auth = base64.b64decode(message['encrypted_alice_auth'])
            
            print(f"\n[{self.bob_id}] Получено сообщение от Алисы")
            print(f"[{self.bob_id}] Шаг 1: Расшифровка сообщения от Трента (RSA)")
            
            decrypted_from_trent = self.crypto.decrypt_rsa(self.private_key, encrypted_for_bob)
            trent_message = json.loads(decrypted_from_trent.decode())
            
            self.session_key = base64.b64decode(trent_message['session_key'])
            self.alice_id = trent_message['alice_id']
            timestamp = trent_message['timestamp']
            lifetime = trent_message['lifetime']
            self.alice_host = trent_message.get('alice_host', 'localhost')
            self.alice_port = trent_message.get('alice_port', 10001)
            
            print(f"[{self.bob_id}] Сессионный ключ получен")
            print(f"[{self.bob_id}] Timestamp={timestamp}, Lifetime={lifetime}")
            
            print(f"[{self.bob_id}] Шаг 2: Расшифровка сообщения от Алисы (AES)")
            
            decrypted_alice_auth = self.crypto.decrypt_aes(self.session_key, encrypted_alice_auth)
            alice_message = json.loads(decrypted_alice_auth)
            
            print(f"[{self.bob_id}] Получено подтверждение от {alice_message['alice_id']}")
            print(f"[{self.bob_id}] Время Алисы: {alice_message['timestamp']}")
            
            response_timestamp = alice_message['timestamp'] + 1
            response_message = json.dumps({
                'timestamp': response_timestamp
            }).encode()
            
            print(f"[{self.bob_id}] Шаг 3: Отправка ответа Алисе (время+1)")
            
            encrypted_response = self.crypto.encrypt_aes(self.session_key, response_message)
            
            response = {
                'type': 'auth_response',
                'encrypted_timestamp': base64.b64encode(encrypted_response).decode()
            }
            
            client_socket.sendall(json.dumps(response).encode())
            
            print(f"[{self.bob_id}] Аутентификация успешна!")
            print(f"[{self.bob_id}] Алиса готова к чату\n")
            self.auth_received = True
            
        except Exception as e:
            print(f"[{self.bob_id}] Ошибка обработки: {e}")
        finally:
            client_socket.close()
    
    def _handle_chat_message(self, client_socket):
        """Обрабатывает сообщение чата от Алисы"""
        try:
            data = client_socket.recv(4096)
            if data:
                encrypted_message = base64.b64decode(data)
                decrypted = self.crypto.decrypt_aes(self.session_key, encrypted_message)
                print(f"\n[Алиса] > {decrypted}")
                print(f"[{self.bob_id}] > ", end='', flush=True)
        except Exception as e:
            print(f"[{self.bob_id}] Ошибка приема сообщения: {e}")
        finally:
            client_socket.close()
    
    def send_message(self, message_text):
        """Отправляет сообщение Алисе"""
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.alice_host, self.alice_port))
            
            encrypted_message = self.crypto.encrypt_aes(self.session_key, message_text)
            socket_client.sendall(base64.b64encode(encrypted_message))
            
            socket_client.close()
        except Exception as e:
            print(f"[{self.bob_id}] Ошибка отправки: {e}")
    
    def start_chat(self):
        """Запускает интерактивный чат"""
        print(f"=== Начало чата ===")
        print(f"[{self.bob_id}] (введите 'выход' для завершения)\n")
        print(f"[{self.bob_id}] > ", end='', flush=True)
        
        try:
            while True:
                message = input()
                if message.lower() in ['exit', 'quit', 'выход', '']:
                    break
                
                self.send_message(message)
                print(f"[{self.bob_id}] > ", end='', flush=True)
        except EOFError:
            pass
        except Exception as e:
            print(f"Ошибка: {e}")
        
        print(f"\n[{self.bob_id}] Завершение сеанса")


if __name__ == '__main__':
    bob = Bob(bob_id='Bob', trent_port=9999, bob_host='localhost', bob_port=10002)
    
    print("=== Инициализация Боба ===\n")
    
    if not bob.register_at_trent():
        print("[Боб] Ошибка регистрации, выход")
        exit(1)
    
    print("Подготовка завершена.")
    print("Ожидание запроса аутентификации от Алисы...\n")
    input("Нажмите Enter для начала прослушивания: ")
    print()
    
    bob.start_listening()
    
    try:
        while True:
            time.sleep(1)
            if bob.alice_id is not None and bob.session_key is not None:
                bob.start_chat()
                break
    except KeyboardInterrupt:
        print(f"\n[{bob.bob_id}] Завершение работы")
