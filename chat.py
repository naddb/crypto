from des import main as des_main
import socket
import threading

# Функция для чтения сообщений от клиента
def handle_client(client_socket, client_address):
    print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

    while True:
        # Получаем данные от клиента
        data = client_socket.recv(1024)
        if not data:
            print(f"[-] Connection from {client_address[0]}:{client_address[1]} closed")
            break
        
        # Здесь дешифруем сообщение после получения
        decrypted_message = des_main.Decryption("mykey123", data.decode('utf-8'), padding=True)
        print(f"[*] Received message from {client_address[0]}:{client_address[1]}: {decrypted_message}")

        # Отправляем сообщение обратно клиенту
        client_socket.send("Message received".encode('utf-8'))

    client_socket.close()


# Функция для запуска сервера
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 5555)

    server_socket.bind(server_address)
    server_socket.listen(5)

    print("[*] Server listening on port 5555")

    while True:
        client_socket, client_address = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

# Функция для отправки сообщений от клиента

def send_message():
    while True:
        message = input("Enter your message: ")
           # Здесь шифруем сообщение перед отправкой
        encrypted_message = des_main.Encryption("mykey123", message, padding=True)

        # Создаем сокет для отправки сообщения серверу
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 5555))

        # Отправляем сообщение серверу
        client.send(encrypted_message.encode('utf-8'))

        # Получаем ответ от сервера
        response = client.recv(1024)
        print("[*] Server response:", response.decode('utf-8'))

        client.close()

if __name__ == "__main__":
    # Запускаем сервер в отдельном потоке
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Запускаем клиента для отправки сообщений
    send_message()
