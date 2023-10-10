# Import required modules
import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
HOST = '127.0.0.1'
PORT = 1234 # You can use any port between 0 to 65535
LISTENER_LIMIT = 5
active_clients = [] # List of all currently connected users
keys_read = {} # Dictionary to store public and private keys for each user
keys_write = {}

# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):

    while 1:

            message = client.recv(2048)
            print(message)
            if message:
                     # Received a text message
                    decoded_message = decrypt_message(keys_write[client]['private_key'], message)
                    send_messages_to_all(username, decoded_message)
            else:
                print(f"The message send from client {username} is empty")
     

def generate_keys(client):

    for i in range(2):
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
        public_key = private_key.public_key()
        if i == 0:
            keys_read[client] = {'public_key': public_key, 'private_key': private_key}
        else:
            keys_write[client] = {'public_key': public_key, 'private_key': private_key}

# Function to encrypt a message with a public key
def encrypt_message(public_key, message):
    message_enc = message.encode()
    encrypted_message = public_key.encrypt(
        message_enc,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to decrypt a message with a private key
def decrypt_message(private_key, message):
    decrypted_message = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

# Function to send message to a single client
def send_message_to_client(client, message):
    client.sendall(message)

# Function to send any new message to all the clients that
# are currently connected to this server
def send_messages_to_all(username, message):
    print(message)
    for user in active_clients:
        final_msg = username + '~' + message
        final_msg = encrypt_message(keys_read[user[1]]['public_key'], final_msg)
        send_message_to_client(user[1], final_msg)

# Function to handle client
def client_handler(client):
    while 1:

        username = client.recv(2048).decode('utf-8')
        if username != '':
            active_clients.append((username, client))
            generate_keys(client)
            #gerar outra chave e enviar para o cliente tbm
            private_read_bytes = keys_read[client]['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_write_bytes = keys_write[client]['public_key'].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
           # send_messages_to_all(username, "Acaba de entrar no chat!")
            prompt_message = f"{username} Acaba de entrar no chat!"

            send_message_to_client(client, private_read_bytes)
            time.sleep(4)
            send_message_to_client(client, public_write_bytes)
            
            break
            # time.sleep(3)
            #ERRO AO ENVIAR ESTA MENSAGEM, APARENTEMENTE AS DUAS ULTIMAS ESTAO SENDO ENVIADAS AO MESMO TEMPO
            # send_messages_to_all(username, prompt_message)

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