# Import required modules
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
HOST = '127.0.0.1'
PORT = 1234 # You can use any port between 0 to 65535
LISTENER_LIMIT = 5
active_clients = [] # List of all currently connected users
keys = {} # Dictionary to store public and private keys for each user

# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):

    while 1:
        try:
            message = client.recv(2048)
            print(message)
            if message:
                if message.startswith(b"IMAGE:"):
                    print("É UMA FOTOOOOO")
                    qtds = message[len(b"IMAGE:"):] # TODO: inteiro
                    buffer_imagem = b''
                    for _ in range(int.from_bytes(qtds)):
                        buffer_imagem+=client.recv(2048)
                    # Received image data
                    send_images_to_all(username, buffer_imagem)
                else:
                     # Received a text message
                    decoded_message = message.decode('utf-8')
                    print("DECODED: ", decoded_message)
                    decrypt_message(keys[client]['private_key'], decoded_message)
                    send_messages_to_all(username, decoded_message)
            else:
                print(f"The message send from client {username} is empty")
        except Exception as e:
            print(f"Error while receiving message from {username}: {str(e)}")
            break

def generate_keys(client):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    keys[client] = {'public_key': public_key, 'private_key': private_key}

# Function to encrypt a message with a public key
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to decrypt a message with a private key
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return decrypted_message

# Function to send message to a single client
def send_message_to_client(client, message):
    client.sendall(message.encode())
def send_image_to_client(client, image_data):
    print("PARTE FINAL  ===========================")
    print(image_data)
    client.sendall(image_data)

# Function to send any new message to all the clients that
# are currently connected to this server
def send_messages_to_all(username, message):
    final_msg = username + '~' + message
    for user in active_clients:
        encrypt_message(keys[user[1]]['public_key'], message)
        send_message_to_client(user[1], final_msg)

def send_images_to_all(username, image_data):
    print("IMAGE DATA NA HORA DE ENVIAR PARA TODOS ===========================")
    print(image_data)
    for user in active_clients:
        send_image_to_client(user[1], image_data)
        
# Function to handle client
def client_handler(client):
    while 1:

        username = client.recv(2048).decode('utf-8')
        if username != '':
            active_clients.append((username, client))
            generate_keys(client)
            send_messages_to_all(username, "Acaba de entrar no chat!")
            send_message_to_client(client, keys[client]['public_key'])
            prompt_message = f"{username} Acaba de entrar no chat!"
            send_messages_to_all(username, prompt_message)
            break
        else:
            print("Client username is empty")

    threading.Thread(target=listen_for_messages, args=(client, username, )).start()

# Main function
def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    server.listen(LISTENER_LIMIT)

    while 1:

        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")

        threading.Thread(target=client_handler, args=(client, )).start()


if __name__ == '__main__':
    main()