import socket
import threading
import time
import json
import base64
from cryptography.hazmat.primitives import serialization
from crypto_protocol import CryptoProtocol


class Alice:
    """Участник Алиса в протоколе"""
    
    def __init__(self, alice_id='Alice', bob_id='Bob', trent_host='localhost', trent_port=9999, alice_host='localhost', alice_port=10001):
        self.alice_id = alice_id
        self.bob_id = bob_id
        self.trent_host = trent_host
        self.trent_port = trent_port
        self.alice_host = alice_host
        self.alice_port = alice_port
        self.crypto = CryptoProtocol()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.session_key = None
        self.bob_host = None
        self.bob_port = None
        self.encrypted_for_bob = None
        self.server_socket = None
        self.bob_socket = None
        self.last_timestamp = None
        
    def get_public_key_bytes(self):
        """Получает публичный ключ в формате PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def register_at_trent(self):
        """Алиса регистрирует свой публичный ключ у Трента"""
        print(f"[{self.alice_id}] Регистрация у Трента")
        
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.trent_host, self.trent_port))
            
            message = {
                'type': 'register',
                'user_id': self.alice_id,
                'public_key': base64.b64encode(self.get_public_key_bytes()).decode(),
                'host': self.alice_host,
                'port': self.alice_port
            }
            
            socket_client.sendall(json.dumps(message).encode())
            
            response_data = socket_client.recv(1024)
            response = json.loads(response_data.decode())
            socket_client.close()
            
            if response.get('status') == 'ok':
                print(f"[{self.alice_id}] Успешно зарегистрирована\n")
                return True
            else:
                print(f"[{self.alice_id}] Ошибка регистрации: {response.get('message')}")
                return False
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка подключения к Тренту: {e}")
            return False
    
    def step1_send_to_trent(self):
        """Алиса отправляет запрос к Тренту"""
        print(f"[{self.alice_id}] Шаг 1: Отправка запроса к Тренту")
        
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.trent_host, self.trent_port))
            
            message = {
                'type': 'setup_request',
                'alice_id': self.alice_id,
                'bob_id': self.bob_id
            }
            
            socket_client.sendall(json.dumps(message).encode())
            
            response_data = socket_client.recv(8192)
            response = json.loads(response_data.decode())
            socket_client.close()
            
            return response
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка подключения к Тренту: {e}")
            return None
    
    def step2_receive_from_trent(self, response):
        """Алиса получает ответ от Трента и расшифровывает"""
        print(f"[{self.alice_id}] Шаг 2: Получение ответа от Трента")
        
        try:
            encrypted_for_alice = base64.b64decode(response['encrypted_for_alice'])
            self.encrypted_for_bob = base64.b64decode(response['encrypted_for_bob'])
            
            decrypted_message = self.crypto.decrypt_rsa(self.private_key, encrypted_for_alice)
            message_dict = json.loads(decrypted_message.decode())
            
            self.session_key = base64.b64decode(message_dict['session_key'])
            timestamp = message_dict['timestamp']
            lifetime = message_dict['lifetime']
            self.bob_host = message_dict.get('bob_host', 'localhost')
            self.bob_port = message_dict.get('bob_port', 10002)
            
            print(f"[{self.alice_id}] Получен сессионный ключ")
            print(f"[{self.alice_id}] Timestamp={timestamp}, Lifetime={lifetime}")
            print(f"[{self.alice_id}] Адрес Боба: {self.bob_host}:{self.bob_port}\n")
            return True
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка расшифровки: {e}")
            return False
    
    def step3_send_to_bob(self):
        """Алиса отправляет Бобу сообщение"""
        print(f"[{self.alice_id}] Шаг 3: Отправка сообщения Бобу")
        
        max_retries = 7
        retry_delay = 10
        
        for attempt in range(1, max_retries + 1):
            try:
                self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.bob_socket.connect((self.bob_host, self.bob_port))
                
                self.last_timestamp = int(time.time())
                alice_auth = json.dumps({
                    'alice_id': self.alice_id,
                    'timestamp': self.last_timestamp
                }).encode()
                
                encrypted_auth = self.crypto.encrypt_aes(self.session_key, alice_auth)
                
                message = {
                    'type': 'auth_message',
                    'encrypted_for_bob': base64.b64encode(self.encrypted_for_bob).decode(),
                    'encrypted_alice_auth': base64.b64encode(encrypted_auth).decode()
                }
                
                self.bob_socket.sendall(json.dumps(message).encode())
                print(f"[{self.alice_id}] Сообщение отправлено (попытка {attempt}/{max_retries}, время: {self.last_timestamp})")
                
                response_data = self.bob_socket.recv(1024)
                response = json.loads(response_data.decode())
                
                return response
            except Exception as e:
                print(f"[{self.alice_id}] Ошибка попытки {attempt}/{max_retries}: {e}")
                
                if attempt < max_retries:
                    print(f"[{self.alice_id}] Повторная попытка через {retry_delay} сек...")
                    time.sleep(retry_delay)
                else:
                    print(f"[{self.alice_id}] Все попытки исчерпаны!")
                    return None
        
        return None
    
    def step4_verify_bob(self, response):
        """Алиса проверяет ответ от Боба"""
        print(f"[{self.alice_id}] Шаг 4: Проверка ответа от Боба")
        
        try:
            encrypted_timestamp = base64.b64decode(response['encrypted_timestamp'])
            decrypted = self.crypto.decrypt_aes(self.session_key, encrypted_timestamp)
            message_dict = json.loads(decrypted)
            
            bob_timestamp = message_dict['timestamp']
            expected_timestamp = self.last_timestamp + 1
            
            if bob_timestamp != expected_timestamp:
                raise Exception(f"Неверная временная метка! Ожидалась {expected_timestamp}, получена {bob_timestamp}")
            
            print(f"[{self.alice_id}] Проверка пройдена! Боб подтвердил время: {bob_timestamp}")
            print(f"[{self.alice_id}] Аутентификация успешна!\n")
            return True
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка проверки: {e}")
            return False
    
    def start_listening(self):
        """Запускает сервер для приема сообщений от Bob"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.alice_host, self.alice_port))
        self.server_socket.listen(5)
        print(f"[{self.alice_id}] Слушает на {self.alice_host}:{self.alice_port}\n")
        
        thread = threading.Thread(target=self._accept_messages, daemon=True)
        thread.start()
    
    def _accept_messages(self):
        """Принимает сообщения для чата"""
        while True:
            try:
                self.server_socket.settimeout(1)
                client_socket, addr = self.server_socket.accept()
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
    
    def _handle_chat_message(self, client_socket):
        """Обрабатывает сообщение чата"""
        try:
            data = client_socket.recv(4096)
            if data:
                encrypted_message = base64.b64decode(data)
                decrypted = self.crypto.decrypt_aes(self.session_key, encrypted_message)
                print(f"\n[Боб] > {decrypted}")
                print(f"[{self.alice_id}] > ", end='', flush=True)
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка чата: {e}")
        finally:
            client_socket.close()
    
    def send_message(self, message_text):
        """Отправляет сообщение Бобу"""
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.bob_host, self.bob_port))
            
            encrypted_message = self.crypto.encrypt_aes(self.session_key, message_text)
            socket_client.sendall(base64.b64encode(encrypted_message))
            
            socket_client.close()
        except Exception as e:
            print(f"[{self.alice_id}] Ошибка отправки: {e}")
    
    def run_protocol(self):
        """Запускает протокол аутентификации"""
        if not self.register_at_trent():
            return False
        
        self.start_listening()
        time.sleep(1)
        
        response = self.step1_send_to_trent()
        if response is None:
            print(f"[{self.alice_id}] Не удалось подключиться к Тренту")
            return False
        
        if not self.step2_receive_from_trent(response):
            return False
        
        time.sleep(0.5)
        
        response_bob = self.step3_send_to_bob()
        if response_bob is None:
            print(f"[{self.alice_id}] Не удалось подключиться к Бобу")
            return False
        
        time.sleep(0.5)
        
        if not self.step4_verify_bob(response_bob):
            return False
        
        return True
    
    def start_chat(self):
        """Запускает интерактивный чат"""
        print(f"=== Начало чата ===")
        print(f"[{self.alice_id}] (введите 'выход' для завершения)\n")
        print(f"[{self.alice_id}] > ", end='', flush=True)
        
        try:
            while True:
                message = input()
                if message.lower() in ['exit', 'quit', 'выход', '']:
                    break
                
                self.send_message(message)
                print(f"[{self.alice_id}] > ", end='', flush=True)
        except EOFError:
            pass
        except Exception as e:
            print(f"Ошибка: {e}")
        
        print(f"\n[{self.alice_id}] Завершение сеанса")


if __name__ == '__main__':
    alice = Alice(alice_id='Alice', bob_id='Bob', trent_port=9999, alice_host='localhost', alice_port=10001)
    
    print("=== Инициализация Alice ===\n")
    
    print("Подготовка к протоколу аутентификации...")
    print("Убедитесь, что Трент и Боб запущены.\n")
    input("Нажмите Enter для начала протокола: ")
    print()
    
    if alice.run_protocol():
        alice.start_chat()
