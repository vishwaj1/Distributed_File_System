####### SERVER1 CODE#########
import socket
import threading
import os
import base64
import pickle
import shutil
from pyaes import AESModeOfOperationCTR, Counter
from pbkdf2 import PBKDF2

# Server's file system root path
SERVER_ROOT_PATH = 'C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/'

# Cryptography settings
AES_PASSWORD = "s3cr3t*c0d3"
AES_PASSWORD_SALT = '76895'

def get_aes_key():
    """Generate and return an AES key derived from a password and salt."""
    return PBKDF2(AES_PASSWORD, AES_PASSWORD_SALT).read(32)

def decrypt_data(encrypted_data):
    """Decrypt and return the given data using AES."""
    aes = AESModeOfOperationCTR(get_aes_key(), Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    return aes.decrypt(encrypted_data).decode('utf-8')

def handle_client_request(client_socket, client_address):
    """Handle requests from a connected client."""
    print(f'Request received from {client_address}')
    while True:
        data = client_socket.recv(100000)
        if not data:
            break  

        # Unpack the data
        dataset = pickle.loads(data)
        request = dataset[0]
        user = dataset[1]
        dirname = decrypt_data(base64.b64decode(dataset[2]))

        # Process the request
        user_dir_path = os.path.join(SERVER_ROOT_PATH, user)
        dir_path = os.path.join(user_dir_path, dirname)

        if request == "createdir":
            os.makedirs(dir_path, exist_ok=True)
            client_socket.sendall("Directory Created".encode())
            print(f"Directory Created: {dirname}")

        elif request == "createfile":
            filename = decrypt_data(base64.b64decode(dataset[3]))
            file_path = os.path.join(dir_path, filename)
            if not os.path.exists(dir_path):
                client_socket.sendall("Given path does not exists".encode())
                print("Given path does not exists: ", file_path)
            else:
                with open(file_path, 'w') as file:
                    file.close()
                client_socket.sendall("File Created".encode())
                print("File Created: ", file_path)

        elif request == "deletefile":
            user = dataset[1]
            encoded_dirname = dataset[2]
            encoded_filename = dataset[3]

            # Decode and decrypt directory and file names
            dirname = decrypt_data(base64.b64decode(encoded_dirname))
            filename = decrypt_data(base64.b64decode(encoded_filename))

            # Construct the file path
            file_path = os.path.join(SERVER_ROOT_PATH, user, dirname, filename)

            # Check if the path exists and determine whether it's a file or directory
            if os.path.isdir(file_path):
                shutil.rmtree(file_path)  # Remove directory and all its contents
                client_socket.sendall("Directory deleted".encode())
                print(f"Directory deleted: {file_path}")
            elif os.path.isfile(file_path):
                os.remove(file_path)  # Remove file
                client_socket.sendall("File deleted".encode())
                print(f"File deleted: {file_path}")
            else:
                client_socket.sendall("File deleted succesfully".encode())
                print(f"File deleted successfully")

        elif request == "writefile":
    
            user = dataset[1]
            encoded_dirname = dataset[2]
            encoded_filename = dataset[3]
            file_content = dataset[4]  # Assuming this is already the decrypted content to write

            # Decode and decrypt directory and file names
            dirname = decrypt_data(base64.b64decode(encoded_dirname))
            filename = decrypt_data(base64.b64decode(encoded_filename))

            # Construct the file path
            file_path = os.path.join(SERVER_ROOT_PATH, user, dirname, filename)

            # Check if the path exists and write to the file
            if os.path.exists(file_path):
                with open(file_path, "w") as file:
                    file.write(file_content)
                client_socket.sendall("File data saved at server".encode())
                print(f"File data saved at server: {filename}")
            else:
                client_socket.sendall("File does not exist".encode())
                print(f"File does not exist: {filename}")

        elif request == "recycle":
            user = dataset[1]
            encoded_dirname = dataset[2]
            encoded_filename = dataset[3]

            # Decode and decrypt directory and file names
            dirname = decrypt_data(base64.b64decode(encoded_dirname))
            filename = decrypt_data(base64.b64decode(encoded_filename))

            # Construct the file path (assuming recycling involves a specific action on the file)
            file_path = os.path.join(SERVER_ROOT_PATH, user, dirname, filename)

            # Send a confirmation message back to the client
            client_socket.sendall("File restored successfully".encode())
            print(f"File restored: {file_path}")


        elif request == "readfile":
            user = dataset[1]
            encoded_dirname = dataset[2]
            encoded_filename = dataset[3]
            # Decode and decrypt directory and file names
            dirname = decrypt_data(base64.b64decode(encoded_dirname))
            filename = decrypt_data(base64.b64decode(encoded_filename))
            # Construct the file path
            file_path = os.path.join(SERVER_ROOT_PATH, user, dirname, filename)
            # Check if the file exists and read its contents
            response = []
            if os.path.exists(file_path):
                with open(file_path, 'r') as file:
                    data = file.read()
                response.append("correct")
                response.append(data)
                print(f"File sent to server: {filename}")
            else:
                response.append("incorrect")
                print(f"File does not exist: {file_path}")

            # Send the response to the client
            response_data = pickle.dumps(response)
            client_socket.sendall(response_data)

    client_socket.close()

def start_server():
    """Start the server and listen for incoming client connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 2778))
    server_socket.listen(4)
    print("Server started. Waiting for connections...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_request, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server_socket.close()

#calling the start_server() function
start_server()
