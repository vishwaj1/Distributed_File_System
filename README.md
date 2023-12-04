# PCS_PROJECT_TEAM7

# Introduction:

A peer-to-peer system is a computer network that enables peers to share network resources. The File System supports all the file operations that other systems do, like creating, reading, deleting, Updating retrieving files, Etc. The File system encrypts all the data from unauthorized users and attackers so that only authorized users have access to the files. The file access can be shared with other users.

# Features:

# User Authentication:
Users can log in with existing credentials or sign up for a new account.
User registration details are securely stored in a MySQL database.

# File Operations:

1. Create Directories: Users can create directories to organize their files.
2. Create/Delete Files: Users can create and delete files within the system.
3. Read/Write File Content: Read and write operations are supported for file contents.
4. Rename Files: Users can rename files for better organization.
5. Share Access: File access can be shared with other users with specified access modes (Read/Write).
6. List Available Files: Users can view the list of available files for efficient management.

# Security:
The system employs Advanced Encryption Standard (AES) for secure data transmission between the Peers.
User credentials and sensitive data are protected during communication.

#Database Interaction:
User registration details and file access control information are stored in a MySQL database.
The database ensures data integrity and provides a reliable storage solution for user-related information.

Working of the System:
# User Authentication:
Users log in using their credentials or sign up for a new account.
Usernames and passwords are validated against the stored records in the MySQL database.

File Operations:
Users interact with a graphical user interface (GUI) to perform file operations.
The system communicates with the server over sockets to execute file-related requests.
Secure AES encryption ensures the confidentiality of data during transmission.

Database Interaction:
User registration details, including usernames, passwords, and contact information, are stored securely.
File access control details, such as sharing and permission information, are managed in the database.

List Available Files:
Users can view the list of available files, including those they own and those shared with them by other users.

# Conclusion:
The Peer-to-peer Encrypted File System offers a robust and secure solution for users to manage files efficiently in a distributed environment. It combines user-friendly features with data security, making it an ideal choice for users requiring remote file management capabilities. The integration of a MySQL database ensures reliable storage and retrieval of user and access control details. The system's use of AES encryption guarantees the confidentiality and integrity of data during communication.

# Implementation
Download this git repository to your local file and use any code editor to run the code which could run python script.
Step 1 : Connect to mysql database and create tables as given in database.txt
Step 2 : Check the port number and ip address so that it matches with the mySQL server
Step 3 : Run server.py file #Server gets started
Step 4 : Run Server2.py
Step 5 : Run client.py 

After running client a gui is opened with login and signup page, after signup you can login. After login you can perform all the functions using the GUI.
