import time as time_lib
import pymysql as db_connector
import tkinter.font as tk_font
from tkinter import messagebox as tk_messagebox
from tkinter import Tk, END, Scrollbar, Text, Frame, Button, Checkbutton, Label, Canvas, Listbox, Entry, PhotoImage, Toplevel, StringVar
from tkinter import simpledialog as tk_simpledialog
from tkinter import filedialog as tk_filedialog
import tkinter as tk
from tkinter import ttk as tk_ttk
import socket as net_socket
import pickle as data_pickle
import pyaes
import pbkdf2 as pbkdf2_lib
import base64 as base64_lib
import shutil as file_shutil
from PIL import ImageTk as pil_imageTk, Image as pil_image
import logging as logging_lib


main_interface = Tk()
main_interface.rowconfigure(0, weight=1)
main_interface.columnconfigure(0, weight=1)
main_interface.state('zoomed')
main_interface.resizable(0, 0)
main_interface.title('User Authentication Interface')

global auth_username, auth_password, reg_username, reg_password, user_contact, active_username, action_counter, reg_window, login_window, display_text, directory_path, file_selector, permission_selector
action_counter = 0
global file_library, main_path
main_path = 'C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/'
logging_lib.basicConfig(filename='system_activity.log', level=logging_lib.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def record_file_read(user_id, file_id, access_level):
    logging_lib.info('File Read: %s User %s accessed %s', access_level, user_id, file_id)

def record_file_write(user_id, file_id, access_level):
    logging_lib.info('File Write: %s User %s modified %s', access_level, user_id, file_id)

def record_file_delete(user_id, file_id, access_level):
    logging_lib.info('File Delete: %s User %s removed %s', access_level, user_id, file_id)

def display_log_entries():
    display_text.delete('1.0', 'end')
    with open('system_activity.log', 'r') as activity_log:
        log_records = activity_log.readlines()
    for record in log_records:
        newline = '\n'
        display_text.insert(END, record.strip())
        display_text.insert(END, newline)

def generate_encryption_key():  # Generating key with PBKDF2 for AES
    secret_key = "mySecretKey123"
    key_salt = '123456'
    encryption_key = pbkdf2_lib.PBKDF2(secret_key, key_salt).read(32)
    return encryption_key

def encrypt_data(data_to_encrypt):  # AES data encryption
    aes_encryptor = pyaes.AESModeOfOperationCTR(generate_encryption_key(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    encrypted_data = aes_encryptor.encrypt(data_to_encrypt)
    return encrypted_data

def decrypt_data(encrypted_data):  # AES data decryption
    aes_decryptor = pyaes.AESModeOfOperationCTR(generate_encryption_key(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted_data = aes_decryptor.decrypt(encrypted_data)
    return decrypted_data

def initiateDirectoryCreation():
   global active_user, display_text
    global directory_name
    directory_name = tk_simpledialog.askstring(title="Enter Directory Name", prompt="Enter Directory Name")
    directory_name = encrypt_data(directory_name)
    directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2778))
    directory_info = []
    directory_info.append("createdir")
    directory_info.append(active_user)
    directory_info.append(directory_name)
    directory_info = data_pickle.dumps(directory_info)
    server_socket.send(directory_info)
    response = server_socket.recv(100)
    response = response.decode()

    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2227))
    server_socket.send(directory_info)
    response = server_socket.recv(100)
    response = response.decode()
    display_text.insert(END, response + "\n")

def uploadFileToServer():
    target_directory = "C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/Uploads"
    selected_file_path = tk_filedialog.askopenfilename()
    try:
        file_shutil.copy(selected_file_path, target_directory)
        print("File successfully uploaded!")
        upload_response = "File successfully uploaded"
    except Exception as upload_error:
        print(f"Error uploading file: {upload_error}")
        upload_response = f"Error uploading file: {upload_error}"
    display_text.insert(END, upload_response + "\n")

def generateNewFile():
    global active_user, display_text
    global directory_name
    directory_name = tk_simpledialog.askstring(title="Enter Directory Name", prompt="Enter Directory Name")
    file_name = tk_simpledialog.askstring(title="Enter File Name", prompt="Enter File Name")
    directory_name = encrypt_data(directory_name)
    directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
    file_name = encrypt_data(file_name)
    file_name = str(base64_lib.b64encode(file_name), 'utf-8')
    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2778))
    file_details = []
    file_details.append("createfile")
    file_details.append(active_user)
    file_details.append(directory_name)
    file_details.append(file_name)
    file_details = data_pickle.dumps(file_details)
    server_socket.send(file_details)
    response = server_socket.recv(100)
    response = response.decode()
    directory_name = base64_lib.b64decode(directory_name)
    directory_name = decrypt_data(directory_name)
    directory_name = directory_name.decode("utf-8")
    file_name = base64_lib.b64decode(file_name)
    file_name = decrypt_data(file_name)
    file_name = file_name.decode("utf-8")
    if response != 'file does not exist':
        db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
        db_cursor = db_connection.cursor()
        file_insert_query = "INSERT INTO all_files(owner, file) VALUES('" + active_user + "','" + main_path + active_user + "/" + directory_name + "/" + file_name + "')"
        db_cursor.execute(file_insert_query)
        db_connection.commit()
        file_library.append(main_path + active_user + "/" + directory_name + "/" + file_name)
        file_selection['values'] = file_library

    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2227))
    server_socket.send(file_details)
    display_text.insert(END, response + "\n")
    
def removeFileFromServer():
     global active_user, display_text
    global directory_name
    directory_name = file_selection.get()
    original_file_path = directory_name
    path_elements = directory_name.split("/")
    file_owner = path_elements[6]
    directory_name = path_elements[7]
    file_name = path_elements[8]
    directory_name = encrypt_data(directory_name)
    directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
    deletion_allowed = False
    no_access = 'None'
    delete_access = 'Delete'
    if file_owner != active_user:
        db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
        with db_connection:
            db_cursor = db_connection.cursor()
            db_cursor.execute("SELECT access_mode FROM access WHERE user=%s AND filename=%s", (active_user, file_selection.get()))
            access_rows = db_cursor.fetchall()
            for access_row in access_rows:
                if access_row[0] == delete_access:
                    deletion_allowed = True
    user_permission = 'unauthorized'
    if file_owner == active_user or deletion_allowed:
        user_permission = 'authorized'
        record_file_delete(active_user, file_name, user_permission)
        backup_path = 'C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/Recycle/' + file_name
        try:
            file_shutil.move(original_file_path, backup_path)
            print(f"Successfully moved file from {original_file_path} to {backup_path}")
        except Exception as move_error:
            print(f"Error: {move_error}")
        file_name = encrypt_data(file_name)
        file_name = str(base64_lib.b64encode(file_name), 'utf-8')
        server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
        server_socket.connect(('localhost', 2778))
        file_info = []
        file_info.append("deletefile")
        file_info.append(file_owner)
        file_info.append(directory_name)
        file_info.append(file_name)
        file_info = data_pickle.dumps(file_info)
        server_socket.send(file_info)
        response = server_socket.recv(100)
        response = response.decode()
        display_text.insert(END, response + "\n")
        if original_file_path in file_library:
            print("Me")
            file_library.remove(original_file_path)
        db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
        db_cursor = db_connection.cursor()
        delete_query = "DELETE FROM all_files WHERE file=%s"
        db_cursor.execute(delete_query, original_file_path)
        db_connection.commit()
    else:
        tk_messagebox.showinfo("No Permission to Delete File", active_user + " does not have permission to delete file " + file_owner)
        record_file_delete(active_user, file_name, user_permission)

def editFileContent():
    global active_user, display_text
    global directory_name
    directory_name = file_selection.get()
    path_parts = directory_name.split("/")
    owner_name = path_parts[6]
    directory_name = path_parts[7]
    file_name = path_parts[8]
    directory_name = encrypt_data(directory_name)
    directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
    write_access_granted = False
    no_permission = 'None'
    write_permission = 'Write'
    if owner_name != active_user:
        db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
        with db_connection:
            db_cursor = db_connection.cursor()
            db_cursor.execute("SELECT access_mode FROM access WHERE user=%s AND filename=%s", (active_user, file_selection.get()))
            access_modes = db_cursor.fetchall()
            for access_mode in access_modes:
                if access_mode[0] == write_permission:
                    write_access_granted = True
    user_permission = 'unauthorized'
    if owner_name == active_user or write_access_granted:
        user_permission = 'authorized'
        record_file_write(active_user, file_name, user_permission)
        file_name = encrypt_data(file_name)
        file_name = str(base64_lib.b64encode(file_name), 'utf-8')

        file_content = tk_simpledialog.askstring(title="Enter File Content", prompt="Enter File Content")
        file_content = encrypt_data(file_content)
        file_content = str(base64_lib.b64encode(file_content), 'utf-8')
        server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
        server_socket.connect(('localhost', 2778))
        file_details = []
        file_details.append("writefile")
        file_details.append(owner_name)
        file_details.append(directory_name)
        file_details.append(file_name)
        file_details.append(file_content)
        file_details = data_pickle.dumps(file_details)
        server_socket.send(file_details)
        response = server_socket.recv(100)
        response = response.decode()
        display_text.insert(END, response + "\n")

        server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
        server_socket.connect(('localhost', 2227))
        file_details = data_pickle.dumps(file_details)
        server_socket.send(file_details)
    else:
        tk_messagebox.showinfo("No Permission to Edit File", active_user + " does not have permission to edit file " + owner_name)
        record_file_write(active_user, file_name, user_permission)

def restoreFileFromRecycleBin():
    global active_user, display_text, permission_options
    global directory_name
    directory_name = tk_simpledialog.askstring(title="Enter Directory Name for Restore", prompt="Enter Directory Name")
    dir_to_restore = directory_name
    file_to_restore = tk_simpledialog.askstring(title="Enter File Name for Restore", prompt="Enter File Name to Restore")
    file_label = file_to_restore
    restore_target_path = main_path + active_user + "/" + directory_name + "/" + file_to_restore
    original_file_path = 'C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/Recycle/' + file_to_restore
    try:
        file_shutil.move(original_file_path, restore_target_path)
        print(f"Successfully moved file from {original_file_path} to {restore_target_path}")
    except Exception as move_error:
        print(f"Error: {move_error}")
    directory_name = encrypt_data(directory_name)
    directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
    file_name_encoded = encrypt_data(file_to_restore)
    file_name_encoded = str(base64_lib.b64encode(file_name_encoded), 'utf-8')
    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2778))
    file_info = []
    file_info.append("recycle")
    file_info.append(active_user)
    file_info.append(directory_name)
    file_info.append(file_name_encoded)
    file_info = data_pickle.dumps(file_info)
    server_socket.send(file_info)
    response = server_socket.recv(100)
    response = response.decode()
    file_library.append(restore_target_path)
    db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
    db_cursor = db_connection.cursor()
    file_insert_query = "INSERT INTO all_files(owner, file) VALUES('" + active_user + "','" + main_path + active_user + "/" + dir_to_restore + "/" + file_label + "')"
    db_cursor.execute(file_insert_query)
    db_connection.commit()
    server_socket = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
    server_socket.connect(('localhost', 2227))
    server_socket.send(file_info)
    response = server_socket.recv(100)
    response = response.decode()
    display_text.insert(END, response + "\n")
    
def allocateFileAccess():
    global active_user, display_text, permission_options
    global directory_name
    directory_name = file_selection.get()
    directory_name = directory_name.replace("\\", "/")
    recipient_user = tk_simpledialog.askstring(title="Enter Username to Share File With", prompt="Enter Username to Share File With")
    selected_access_mode = permission_options.get()

    db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
    db_cursor = db_connection.cursor()
    access_control_query = "INSERT INTO access(owner, user, filename, access_mode) VALUES(%s, %s, %s, %s)"
    db_cursor.execute(access_control_query, (active_user, recipient_user, directory_name, selected_access_mode))
    db_connection.commit()
    tk_messagebox.showinfo("Access Control Updated", "File access control details updated in database")
    
def readFile():
    global active_user, display_text
    global directory_name
    display_text.delete('1.0', END)
    directory_name = file_selection.get()
    directory_name = directory_name.replace("\\", "/")
    arr = directory_name.split("/")
    file_owner = arr[6]
    directory_name = arr[7]
    file_name = arr[8]
    directory_name = directory_name
    file_name = file_name
    permission_status = False
    read_permission = "Read"
    no_permission = 'None'

    if file_owner != active_user:
        db_connection = db_connector.connect(host='127.0.0.1', port=3306, user='root', password='Sathvik@007', database='distributed', charset='utf8')
        with db_connection:
            db_cursor = db_connection.cursor()
            query = "SELECT access_mode FROM access WHERE user=%s AND filename=%s"
            db_cursor.execute(query, (active_user, file_selection.get()))
            result = db_cursor.fetchall()
            for row in result:
                if row[0] == read_permission:
                    permission_status = True

    permission = 'unauthorized'
    print(file_owner)
    print(permission_status)
    if file_owner == active_user or permission_status:
        permission = 'authorized'
        record_file_read(active_user, file_name, permission)
        directory_name = encrypt_data(directory_name)
        directory_name = str(base64_lib.b64encode(directory_name), 'utf-8')
        file_name = encrypt_data(file_name)
        file_name = str(base64_lib.b64encode(file_name), 'utf-8')
        client = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
        client.connect(('localhost', 2778))
        features = ["readfile", file_owner, directory_name, file_name]
        features = data_pickle.dumps(features)
        client.send(features)
        received_data = client.recv(10000)
        dataset = data_pickle.loads(received_data)
        request = dataset[0]
        
        if request == "correct":
            data = dataset[1]
            data = base64_lib.b64decode(data)
            data = decrypt_data(data)
            data = data.decode("utf-8")
            display_text.insert(END, "File Content Showing in Below lines\n\n")
            display_text.insert(END, data)
        else:
            display_text.insert(END, "File does not exist\n")
        
        client1 = net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM)
        client1.connect(('localhost', 2227))
        client1.send(features)
    else:
        tk_messagebox.showinfo("Permission Denied", f"{active_user}, you don't have permission to read this file owned by {file_owner}")
        record_file_read(active_user, file_name, permission)

def readFiles():
    global file_library
    if len(file_library) > 0:
        file_library.clear()
    file_library.append("Available Files")
    con = db_connector.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'Sathvik@007', database = 'distributed',charset='utf8')
    with con:
        cur = con.cursor()
        cur.execute("select file FROM all_files")
        rows = cur.fetchall()
        for row in rows:
            file_library.append(row[0])

def fileManagementSystem():
    global active_user, display_text, file_library, file_selection, permission_options

    # Initialize the main window
    file_sys_window = tk.Tk()
    file_sys_window.title("File Management System Interface")
    file_sys_window.geometry("1300x900")
    standard_font = tk_font.Font(family='Helvetica', size=12, weight='bold')

    # Create a frame for file operations
    operation_frame = tk.Frame(file_sys_window, bg='blue', bd=2, relief='groove')
    operation_frame.place(x=20, y=20, width=1260, height=120)

    # Directory Creation Button
    createDirButton = Button(operation_frame, text="Create Directory", command=initiateDirectoryCreation, font=standard_font)
    createDirButton.place(x=10, y=10)

    # File Creation Button
    createFileButton = Button(operation_frame, text="Create File", command=generateNewFile, font=standard_font)
    createFileButton.place(x=180, y=10)

    # File Upload Button
    uploadFileButton = Button(operation_frame, text="Upload File", command=uploadFileToServer, font=standard_font)
    uploadFileButton.place(x=350, y=10)

    # File Deletion Button
    deleteFileButton = Button(operation_frame, text="Delete File", command=removeFileFromServer, font=standard_font)
    deleteFileButton.place(x=520, y=10)

    # File Restore Button
    restoreFileButton = Button(operation_frame, text="Restore File", command=restoreFileFromRecycleBin, font=standard_font)
    restoreFileButton.place(x=690, y=10)

    # File Reading Button
    readFileButton = Button(operation_frame, text="Read File", command=readFile, font=standard_font)
    readFileButton.place(x=860, y=10)

    # File Writing Button
    writeFileButton = Button(operation_frame, text="Write File", command=editFileContent, font=standard_font)
    writeFileButton.place(x=1030, y=10)

    # Access Sharing Button
    shareAccessButton = Button(operation_frame, text="Share Access", command=allocateFileAccess, font=standard_font)
    shareAccessButton.place(x=860, y=60)

    # Log Display Button
    displayLogButton = Button(operation_frame, text="Display Log", command=display_log_entries, font=standard_font)
    displayLogButton.place(x=180, y=60)

    # File Selection Combobox
    file_selection = tk_ttk.Combobox(operation_frame, values=file_library, font=standard_font)
    file_selection.place(x=350, y=65, width=320)
    if len(file_library) > 0:
        file_selection.current(0)

    # Access Control Combobox
    permission_options = tk_ttk.Combobox(operation_frame, values=['Read', 'Write', 'Rename', 'Delete'], font=standard_font)
    permission_options.place(x=690, y=65, width=150)
    permission_options.current(0)

    # Text Box for Logs or File Content
    text_frame = Frame(file_sys_window)
    text_frame.place(x=20, y=160, width=1260, height=720)

    display_text = Text(text_frame, bg='white', fg='black', font=standard_font)
    display_text.pack(side='left', fill='both', expand=True)

    scrollbar = Scrollbar(text_frame, command=display_text.yview)
    scrollbar.pack(side='right', fill='y')

    display_text['yscrollcommand'] = scrollbar.set

    # Mainloop
    file_sys_window.mainloop()

# Window Icon Photo
icon = PhotoImage(file='images\\pic-icon.png')
main_interface.iconphoto(True, icon)

LoginPage = Frame(main_interface)
RegistrationPage = Frame(main_interface)

for frame in (LoginPage, RegistrationPage):
    frame.grid(row=0, column=0, sticky='nsew')


def show_frame(frame):
    frame.tkraise()


show_frame(LoginPage)


# ========== DATABASE VARIABLES ============
Email = StringVar()
FullName = StringVar()
Password = StringVar()
ConfirmPassword = StringVar()

design_frame1 = Listbox(LoginPage, bg='#0c71b9', width=115, height=50, highlightthickness=0, borderwidth=0)
design_frame1.place(x=0, y=0)

design_frame2 = Listbox(LoginPage, bg='#1e85d0', width=115, height=50, highlightthickness=0, borderwidth=0)
design_frame2.place(x=676, y=0)

design_frame3 = Listbox(LoginPage, bg='#1e85d0', width=100, height=33, highlightthickness=0, borderwidth=0)
design_frame3.place(x=75, y=106)

design_frame4 = Listbox(LoginPage, bg='#f8f8f8', width=100, height=33, highlightthickness=0, borderwidth=0)
design_frame4.place(x=676, y=106)

# ====== Usernme ====================
email_entry = Entry(design_frame4, fg="#a7a7a7", font=("yu gothic ui semibold", 12), highlightthickness=2,
                    textvariable=Email)
email_entry.place(x=134, y=170, width=256, height=34)
email_entry.config(highlightbackground="black", highlightcolor="black")
email_label = Label(design_frame4, text='• Username', fg="#89898b", bg='#f8f8f8', font=("yu gothic ui", 11, 'bold'))
email_label.place(x=130, y=140)

# ==== Password ==================
password_entry1 = Entry(design_frame4, fg="#a7a7a7", font=("yu gothic ui semibold", 12), show='•', highlightthickness=2,
                        textvariable=Password)
password_entry1.place(x=134, y=250, width=256, height=34)
password_entry1.config(highlightbackground="black", highlightcolor="black")
password_label = Label(design_frame4, text='• Password', fg="#89898b", bg='#f8f8f8', font=("yu gothic ui", 11, 'bold'))
password_label.place(x=130, y=220)


# function for show and hide password
def password_command():
    if password_entry1.cget('show') == '•':
        password_entry1.config(show='')
    else:
        password_entry1.config(show='•')


# ====== checkbutton ==============
checkButton = Checkbutton(design_frame4, bg='#f8f8f8', command=password_command, text='show password')
checkButton.place(x=140, y=288)

# ========= Buttons ===============
SignUp_button = Button(LoginPage, text='Sign up', font=("yu gothic ui bold", 12), bg='#f8f8f8', fg="#89898b",
                       command=lambda: show_frame(RegistrationPage), borderwidth=0, activebackground='#1b87d2', cursor='hand2')
SignUp_button.place(x=1100, y=175)

# ===== Welcome Label ==============
welcome_label = Label(design_frame4, text='Welcome', font=('Arial', 20, 'bold'), bg='#f8f8f8')
welcome_label.place(x=130, y=15)

# ======= top Login Button =========
login_button = Button(LoginPage, text='Login', font=("yu gothic ui bold", 12), bg='#f8f8f8', fg="#89898b",
                      borderwidth=0, activebackground='#1b87d2', cursor='hand2')
login_button.place(x=845, y=175)

login_line = Canvas(LoginPage, width=60, height=5, bg='#1b87d2')
login_line.place(x=840, y=203)

# ==== LOGIN  down button ============
loginBtn1 = Button(design_frame4, fg='#f8f8f8', text='Login', bg='#1b87d2', font=("yu gothic ui bold", 15),
                   cursor='hand2', activebackground='#1b87d2', command=lambda:login())
loginBtn1.place(x=133, y=340, width=256, height=50)


# ======= ICONS =================

# ===== Name icon =========
email_icon = pil_image.open('images\\name-icon.png')
photo = pil_imageTk.PhotoImage(email_icon)
emailIcon_label = Label(design_frame4, image=photo, bg='#f8f8f8')
emailIcon_label.image = photo
emailIcon_label.place(x=105, y=174)

# ===== password icon =========
password_icon = pil_image.open('images\\pass-icon.png')
photo = pil_imageTk.PhotoImage(password_icon)
password_icon_label = Label(design_frame4, image=photo, bg='#f8f8f8')
password_icon_label.image = photo
password_icon_label.place(x=105, y=254)

# ===== picture icon =========
picture_icon = pil_image.open('images\\pic-icon.png')
photo = pil_imageTk.PhotoImage(picture_icon)
picture_icon_label = Label(design_frame4, image=photo, bg='#f8f8f8')
picture_icon_label.image = photo
picture_icon_label.place(x=280, y=5)

# ===== Left Side Picture ============
side_image = pil_image.open('images\\vector.png')
photo = pil_imageTk.PhotoImage(side_image)
side_image_label = Label(design_frame3, image=photo, bg='#1e85d0')
side_image_label.image = photo
side_image_label.place(x=50, y=10)



def login():
    global login_user, login_pass, active_user, file_library, winsignup
    file_library = []
    usr = email_entry.get()
    password = password_entry1.get()

    output = "none"
    con = db_connector.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'Sathvik@007', database = 'distributed',charset='utf8')
    with con:
        cur = con.cursor()
        cur.execute("select username, password FROM register")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == usr and row[1] == password:
                output = "success"
                active_user = usr
                readFiles()
                break
    if output == "success":
        tk_messagebox.showinfo("Success", 'Logged in Successfully.')
        main_interface.destroy()
        fileManagementSystem()
    else:
        tk_messagebox.showerror("Failed", "Wrong Login details, please try again.")
    



def forgot_password():
    win = Toplevel()
    window_width = 350
    window_height = 350
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    position_top = int(screen_height / 4 - window_height / 4)
    position_right = int(screen_width / 2 - window_width / 2)
    win.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')
    win.title('Forgot Password')
    win.iconbitmap('images\\aa.ico')
    win.configure(background='#f8f8f8')
    win.resizable(0, 0)

    # Variables
    username = StringVar()
    password = StringVar()
    confirmPassword = StringVar()

    # ====== Username ====================
    email_entry2 = Entry(win, fg="#a7a7a7", font=("yu gothic ui semibold", 12), highlightthickness=2,
                         textvariable=username)
    email_entry2.place(x=40, y=30, width=256, height=34)
    email_entry2.config(highlightbackground="black", highlightcolor="black")
    email_label2 = Label(win, text='• Email account', fg="#89898b", bg='#f8f8f8',
                         font=("yu gothic ui", 11, 'bold'))
    email_label2.place(x=40, y=0)

    # ====  New Password ==================
    new_password_entry = Entry(win, fg="#a7a7a7", font=("yu gothic ui semibold", 12), show='•', highlightthickness=2,
                               textvariable=password)
    new_password_entry.place(x=40, y=110, width=256, height=34)
    new_password_entry.config(highlightbackground="black", highlightcolor="black")
    new_password_label = Label(win, text='• New Password', fg="#89898b", bg='#f8f8f8', font=("yu gothic ui", 11, 'bold'))
    new_password_label.place(x=40, y=80)

    # ====  Confirm Password ==================
    confirm_password_entry = Entry(win, fg="#a7a7a7", font=("yu gothic ui semibold", 12), show='•', highlightthickness=2
                                   , textvariable=confirmPassword)
    confirm_password_entry.place(x=40, y=190, width=256, height=34)
    confirm_password_entry.config(highlightbackground="black", highlightcolor="black")
    confirm_password_label = Label(win, text='• Confirm Password', fg="#89898b", bg='#f8f8f8',
                                   font=("yu gothic ui", 11, 'bold'))
    confirm_password_label.place(x=40, y=160)

    # ======= Update password Button ============
    update_pass = Button(win, fg='#f8f8f8', text='Update Password', bg='#1b87d2', font=("yu gothic ui bold", 14),
                         cursor='hand2', activebackground='#1b87d2', command=lambda: change_password())
    update_pass.place(x=40, y=240, width=256, height=50)

    # ========= DATABASE CONNECTION FOR FORGOT PASSWORD=====================
    def change_password():

        if new_password_entry.get() == confirm_password_entry.get():
            con1 = db_connector.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'Sathvik@007', database = 'distributed',charset='utf8')
            with con1:
                cur = con1.cursor()
                query = "update register set password = %s where username = %s "
                cur.execute(query, (new_password_entry.get(),email_entry2.get()))

                
                con1.commit()
                con1.close()
                tk_messagebox.showinfo('Congrats', 'Password changed successfully')

        else:
            tk_messagebox.showerror('Error!', "Passwords didn't match")


forgotPassword = Button(design_frame4, text='Forgot password', font=("yu gothic ui", 8, "bold underline"), bg='#f8f8f8',
                        borderwidth=0, activebackground='#f8f8f8', command=lambda: forgot_password(), cursor="hand2")
forgotPassword.place(x=290, y=290)



design_frame5 = Listbox(RegistrationPage, bg='#0c71b9', width=115, height=50, highlightthickness=0, borderwidth=0)
design_frame5.place(x=0, y=0)

design_frame6 = Listbox(RegistrationPage, bg='#1e85d0', width=115, height=50, highlightthickness=0, borderwidth=0)
design_frame6.place(x=676, y=0)

design_frame7 = Listbox(RegistrationPage, bg='#1e85d0', width=100, height=33, highlightthickness=0, borderwidth=0)
design_frame7.place(x=75, y=106)

design_frame8 = Listbox(RegistrationPage, bg='#f8f8f8', width=100, height=33, highlightthickness=0, borderwidth=0)
design_frame8.place(x=676, y=106)

# ==== Username =======
name_entry = Entry(design_frame8, fg="#a7a7a7", font=("yu gothic ui semibold", 12), highlightthickness=2,
                   textvariable=FullName)
name_entry.place(x=284, y=150, width=286, height=34)
name_entry.config(highlightbackground="black", highlightcolor="black")
name_label = Label(design_frame8, text='•Username', fg="#89898b", bg='#f8f8f8', font=("yu gothic ui", 11, 'bold'))
name_label.place(x=280, y=120)

# ======= Email ===========
email_entry = Entry(design_frame8, fg="#a7a7a7", font=("yu gothic ui semibold", 12), highlightthickness=2,
                    textvariable=Email)
email_entry.place(x=284, y=220, width=286, height=34)
email_entry.config(highlightbackground="black", highlightcolor="black")
email_label = Label(design_frame8, text='•Email', fg="#89898b", bg='#f8f8f8', font=("yu gothic ui", 11, 'bold'))
email_label.place(x=280, y=190)

# ====== Password =========
password_entry = Entry(design_frame8, fg="#a7a7a7", font=("yu gothic ui semibold", 12), show='•', highlightthickness=2,
                       textvariable=Password)
password_entry.place(x=284, y=295, width=286, height=34)
password_entry.config(highlightbackground="black", highlightcolor="black")
password_label = Label(design_frame8, text='• Password', fg="#89898b", bg='#f8f8f8',
                       font=("yu gothic ui", 11, 'bold'))
password_label.place(x=280, y=265)


def password_command2():
    if password_entry.cget('show') == '•':
        password_entry.config(show='')
    else:
        password_entry.config(show='•')


checkButton = Checkbutton(design_frame8, bg='#f8f8f8', command=password_command2, text='show password')
checkButton.place(x=290, y=330)


# ====== Confirm Password =============
confirmPassword_entry = Entry(design_frame8, fg="#a7a7a7", font=("yu gothic ui semibold", 12), highlightthickness=2,
                              textvariable=ConfirmPassword)
confirmPassword_entry.place(x=284, y=385, width=286, height=34)
confirmPassword_entry.config(highlightbackground="black", highlightcolor="black")
confirmPassword_label = Label(design_frame8, text='• Confirm Password', fg="#89898b", bg='#f8f8f8',
                              font=("yu gothic ui", 11, 'bold'))
confirmPassword_label.place(x=280, y=355)

# ========= Buttons ====================
SignUp_button = Button(RegistrationPage, text='Sign up', font=("yu gothic ui bold", 12), bg='#f8f8f8', fg="#89898b",
                       command=lambda: show_frame(LoginPage), borderwidth=0, activebackground='#1b87d2', cursor='hand2')
SignUp_button.place(x=1100, y=175)

SignUp_line = Canvas(RegistrationPage, width=60, height=5, bg='#1b87d2')
SignUp_line.place(x=1100, y=203)

# ===== Welcome Label ==================
welcome_label = Label(design_frame8, text='Welcome', font=('Arial', 20, 'bold'), bg='#f8f8f8')
welcome_label.place(x=130, y=15)

# ========= Login Button =========
login_button = Button(RegistrationPage, text='Login', font=("yu gothic ui bold", 12), bg='#f8f8f8', fg="#89898b",
                      borderwidth=0, activebackground='#1b87d2', command=lambda: show_frame(LoginPage), cursor='hand2')
login_button.place(x=845, y=175)

# ==== SIGN UP down button ============
signUp2 = Button(design_frame8, fg='#f8f8f8', text='Sign Up', bg='#1b87d2', font=("yu gothic ui bold", 15),
                 cursor='hand2', activebackground='#1b87d2', command=lambda: submit())
signUp2.place(x=285, y=435, width=286, height=50)

# ===== password icon =========
password_icon = pil_image.open('images\\pass-icon.png')
photo = pil_imageTk.PhotoImage(password_icon)
password_icon_label = Label(design_frame8, image=photo, bg='#f8f8f8')
password_icon_label.image = photo
password_icon_label.place(x=255, y=300)

# ===== confirm password icon =========
confirmPassword_icon = pil_image.open('images\\pass-icon.png')
photo = pil_imageTk.PhotoImage(confirmPassword_icon)
confirmPassword_icon_label = Label(design_frame8, image=photo, bg='#f8f8f8')
confirmPassword_icon_label.image = photo
confirmPassword_icon_label.place(x=255, y=390)

# ===== Username =========
email_icon = pil_image.open('images\\name-icon.png')
photo = pil_imageTk.PhotoImage(email_icon)
emailIcon_label = Label(design_frame8, image=photo, bg='#f8f8f8')
emailIcon_label.image = photo
emailIcon_label.place(x=255, y=225)

# ===== Full Name icon =========
name_icon = pil_image.open('images\\name-icon.png')
photo = pil_imageTk.PhotoImage(name_icon)
nameIcon_label = Label(design_frame8, image=photo, bg='#f8f8f8')
nameIcon_label.image = photo
nameIcon_label.place(x=252, y=153)

# ===== picture icon =========
picture_icon = pil_image.open('images\\pic-icon.png')
photo = pil_imageTk.PhotoImage(picture_icon)
picture_icon_label = Label(design_frame8, image=photo, bg='#f8f8f8')
picture_icon_label.image = photo
picture_icon_label.place(x=280, y=5)

# ===== Left Side Picture ============
side_image = pil_image.open('images\\vector.png')
photo = pil_imageTk.PhotoImage(side_image)
side_image_label = Label(design_frame7, image=photo, bg='#1e85d0')
side_image_label.image = photo
side_image_label.place(x=50, y=10)

def submit():
    check_counter = 0
    warn = ""
    if name_entry.get() == "":
        warn = "Full Name can't be empty"
    else:
        check_counter += 1

    if email_entry.get() == "":
        warn = "Email Field can't be empty"
    else:
        check_counter += 1

    if password_entry.get() == "":
        warn = "Password can't be empty"
    else:
        check_counter += 1

    if confirmPassword_entry.get() == "":
        warn = "Sorry, can't sign up make sure all fields are complete"
    else:
        check_counter += 1

    if password_entry.get() != confirmPassword_entry.get():
        warn = "Passwords didn't match!"
    else:
        check_counter += 1

    if check_counter == 5:
        global sign_user, sign_pass, contact, active_user, count, winsignup
        usr = name_entry.get()
        password = password_entry.get()
        contactno = email_entry.get()

        output = "none"
        con = db_connector.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'Sathvik@007', database = 'distributed',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == usr:
                    output = active_user+" Username already exists"
                    break                
            if output == "none":
                db_connection = db_connector.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'Sathvik@007', database = 'distributed',charset='utf8')
                db_cursor = db_connection.cursor()
                student_sql_query = "INSERT INTO register(username,password,contact) VALUES('"+usr+"','"+password+"','"+contactno+"')"
                db_cursor.execute(student_sql_query)
                db_connection.commit()
                print(db_cursor.rowcount, "Record Inserted")
                if db_cursor.rowcount == 1:
                    output = "Signup process completed. You can login now"
                    count = 2
                    tk_messagebox.showinfo(output,output)
                    winsignup.destroy()
                    login()
            else:
                tk_messagebox.showinfo(output,output)


main_interface.mainloop()


# def benchmark():
#     start_time = time.time_ns()

#     for i in range(100):
#         readFile('Vishwa','V_a','V6.txt','C:/Users/Chaimama/Desktop/Pcs_Project/cmsc626distributed-file-system-main/Vishwa/V_a/V6.txt')
    
#     elapsed_time = time.time_ns() - start_time

#     print(str(elapsed_time) + "nano seconds")


# benchmark()
