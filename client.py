
import socket
import threading
import tkinter as tk
import io
import pickle
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
from PIL import Image, ImageTk

# Constants and Global Variables
# Server Constants
HOST = '127.0.0.1' #191.8.207.174 / 127.0.0.1
PORT = 1234 #25565 / 1234

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)
keys = {}

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(1000)    #Set how much time will try to connect to server. Can help when the server is Offline.

# Add a message to the Message Box
def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)

# Connect to the server
def connect():
    try:
        # Connect to the server
        client.connect((HOST, PORT))
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except Exception as e:
        # messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")
        add_message(f"[CLIENT] Unable to connect to server {HOST} {PORT}")
        add_message("[CLIENT] Try again later")
        message_box.see(tk.END)
        print(f"Connection error: {e}")
        return()

    # Check valid username
    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    # Create thread to listen messages from erver
    threading.Thread(target=listen_for_messages_from_server, args=(client, )).start()

    # Change state of button JOIN
    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)
    # message_button.config(state=tk.NORMAL)
    # message_textbox.config(state=tk.NORMAL)

# Send a message to server
def send_message():
    message = message_textbox.get()
    if message != '':
        final_msg = encrypt_message(keys["write"]['public'], message)
        client.sendall(final_msg)
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")     

# Listen to messages from the server
def listen_for_messages_from_server(client):
    while True:
        try:
            message = client.recv(2048)
            if message:
                # Check if the received message is a special message
                if(message.startswith(b'--')):
                    message_str = message.decode('utf-8')
                    if "PRIVATE" in message_str:
                        print("ITS A PRIVATE KEY!")
                        private_key = serialization.load_pem_private_key(message, password=None)
                        keys["read"] = {'private': private_key}
                        add_message("[SERVER] Private key received")
                        check_keys()
                        #Tratar se é uma chave publica ou privada, chave privada para leitura, publica para escrita
                    elif "PUBLIC" in message_str:
                        print("ITS A PUBLIC KEY!")
                        public_key = serialization.load_pem_public_key(message)
                        keys["write"] = {'public': public_key}
                        add_message("[SERVER] Public key received")
                        check_keys()

                else:
                    # Received a text message
                    decoded_message = decrypt_message(keys["read"]['private'], message)
                    username = decoded_message.split("~")[0]
                    content = decoded_message.split('~')[1]
                    add_message(f"[{username}] {content}")
                    message_box.see(tk.END)
            else:
                messagebox.showerror("Error", "Message received from the server is empty")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to receive message: {str(e)}")
            exit()

def check_keys():
    if len(keys) == 2:
        message_button.config(state=tk.NORMAL)
        message_textbox.config(state=tk.NORMAL)
        add_message("[CLIENT] Chat Open")

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

# Fuction binded to Enter key event
def on_enter(event):
    # If para mudar a funcao ativado por Enter key.
    if (username_button.cget("state") == "normal"):
        print("Event Enter, Connect")
        connect()
    elif (message_button.cget("state") == "normal"):
        print("Event Enter, Send Message")
        send_message()
    else: 
        print("Event Enter Fail")

# Main GUI
root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

# Window Layout
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

# UI Elements and Widgets
# Username Element
username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

# Message Input Element
message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=32)
message_textbox.pack(side=tk.LEFT, padx=10)
message_textbox.config(state=tk.DISABLED)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=5)
message_button.config(state=tk.DISABLED)

# Message Box Element
message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=100, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)

# Bind Enter key event to on_enter function
root.bind('<Return>', on_enter)

# Main function
def main():
    root.mainloop()
    
if __name__ == '__main__':
    main()