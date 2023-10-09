
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
client.settimeout(1)    #Set how much time will try to connect to server. Can help when the server is Offline.

def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)

def connect():
    try:
        # Connect to the server
        client.connect((HOST, PORT))
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except Exception as e:
        messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}")
        print(f"Connection error: {e}")

    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    threading.Thread(target=listen_for_messages_from_server, args=(client, )).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)

def send_message():
    message = message_textbox.get()
    if message != '':
        client.sendall(message.encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")
def send_image():
    file_path = filedialog.askopenfilename(title="Select an image")

    with open(file_path, 'rb') as image_file:

        #base64_bytes = b'1' + base64.b64encode(image_file.read())
        #print(base64_bytes)
        buffer = image_file.read()
        client.sendall( b"IMAGE:" +bytearray((len(buffer)//2048)+1))
        for i in range(0, len(buffer), 2048):
            client.sendall(buffer[i:i+2048])

#Function binded to event Key_Enter
def on_enter(event):
    send_message()          
    
root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=32)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=5)

img_button = tk.Button(bottom_frame, text="IMG", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_image)
img_button.pack(side=tk.LEFT, padx=4)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=100, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)

#Bind the event Key_Enter to function on_enter
root.bind('<Return>', on_enter)

def listen_for_messages_from_server(client):
    while True:
        #try:
            message = client.recv(2048)
            if message:
                if message.startswith(b"IMAGE:"):
                    # Received image data
                    image_data = message[len(b"IMAGE:"):]
                    add_message( "SERVER","chegou uma foto cacete")
                    #display_received_image(image_data)
                
                elif message.startswith(b"---"):
                    print("ITS A KEY!")

                    private_key = serialization.load_pem_private_key(message, password=None)
                    keys[client] = {'private': private_key}
                    #Tratar se é uma chave publica ou privada, chave privada para leitura, publica para escrita
                else:
                    # Received a text message
                    decoded_message = decrypt_message(keys[client]['private'], message)
                    print(type(decoded_message))
                    username = decoded_message.split("~")[0]
                    content = decoded_message.split('~')[1]
                    add_message(f"[{username}] {content}")
            else:
                messagebox.showerror("Error", "Message received from the server is empty")
        #except Exception as e:
        #    messagebox.showerror("Error", f"Failed to receive message: {str(e)}")

def display_received_image(image_data):
    add_message("Chegou uma imagem :)")
    with Image.frombytes("RGB",(1,100),image_data) as received_image:
        received_image.thumbnail((400, 400))  # Adjust the size as needed
        image_display = ImageTk.PhotoImage(received_image)
        image_label = tk.Label(middle_frame, image=image_display, bg=MEDIUM_GREY)
        image_label.image = image_display
        image_label.pack(side=tk.TOP)

    """
    with pickle.loads(image_data) as received_image:
        received_image.thumbnail((400, 400))  # Adjust the size as needed
        image_display = ImageTk.PhotoImage(received_image)
        image_label = tk.Label(middle_frame, image=image_display, bg=MEDIUM_GREY)
        image_label.image = image_display
        image_label.pack(side=tk.TOP)
    """

# Function to encrypt a message with a public key
def encrypt_message(public_key, message):
    message_enc = message.encode()
    print(type(message_enc))
    print(message_enc)
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

# main function
def main():

    root.mainloop()
    
if __name__ == '__main__':
    main()