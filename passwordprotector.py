import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Hardcoded master key for demonstration purposes
# In practice, securely store and retrieve this key
MASTER_KEY = os.urandom(32)

# Function to derive a key from a password
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Function to encrypt the user-derived key with the master key
def encrypt_user_key_with_master_key(master_key: bytes, user_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_user_key = padder.update(user_key) + padder.finalize()
    
    encrypted_user_key = encryptor.update(padded_user_key) + encryptor.finalize()
    return iv + encrypted_user_key

# Function to decrypt the user-derived key with the master key
def decrypt_user_key_with_master_key(master_key: bytes, encrypted_user_key: bytes) -> bytes:
    iv = encrypted_user_key[:16]
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_user_key = decryptor.update(encrypted_user_key[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_user_key = unpadder.update(decrypted_padded_user_key) + unpadder.finalize()
    
    return decrypted_user_key

# Function to encrypt data
def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + encrypted_data

# Function to decrypt data
def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data

# Function to handle file selection and encryption
def select_file_and_encrypt():
    try:
        # Open file dialog to select file
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        # Read file content
        with open(filepath, 'rb') as file:
            file_content = file.read()

        # Prompt user for a password
        password = simpledialog.askstring("Password", "Enter a password for encryption:", show='*')
        if not password:
            return
        
        # Generate a random salt
        salt = os.urandom(16)
        
        # Derive a key from the password and salt
        key = derive_key_from_password(password, salt)
        
        # Encrypt user-derived key with master key
        encrypted_user_key = encrypt_user_key_with_master_key(MASTER_KEY, key)
        
        # Save the encrypted user key to a file
        with open(filepath + '.key', 'wb') as key_file:
            key_file.write(salt + encrypted_user_key)
        
        # Encrypt the file content
        encrypted_content = encrypt_data(key, file_content)
        
        # Overwrite the original file with the encrypted content
        with open(filepath, 'wb') as file:
            file.write(encrypted_content)

        messagebox.showinfo("Success", f"Your file has been encrypted and saved as {filepath}.\n"
                                       f"The encryption key has been saved as {filepath}.key.\n"
                                       f"Remember your password to decrypt the file.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to handle file selection and decryption
def select_file_and_decrypt():
    try:
        # Open file dialog to select file
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        # Read encrypted file content
        with open(filepath, 'rb') as file:
            encrypted_content = file.read()
        
        # Read the encrypted user key from the key file
        with open(filepath + '.key', 'rb') as key_file:
            key_data = key_file.read()

        # Extract salt and encrypted user key
        salt = key_data[:16]
        encrypted_user_key = key_data[16:]
        
        # Prompt user for the password
        password = simpledialog.askstring("Password", "Enter the password for decryption:", show='*')
        if not password:
            return

        # Derive the key from the password and salt
        key = derive_key_from_password(password, salt)
        
        # Decrypt the user-derived key with the master key
        decrypted_user_key = decrypt_user_key_with_master_key(MASTER_KEY, encrypted_user_key)
        
        # Verify that the decrypted user key matches the derived key
        if key != decrypted_user_key:
            messagebox.showerror("Error", "Incorrect password. Unable to decrypt the file.")
            return

        # Decrypt the data
        decrypted_content = decrypt_data(decrypted_user_key, encrypted_content)

        # Overwrite the encrypted file with the decrypted content
        with open(filepath, 'wb') as file:
            file.write(decrypted_content)

        messagebox.showinfo("Success", f"Your file has been decrypted and saved as {filepath}.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("File Encryptor/Decryptor")
root.geometry("800x600")
root.configure(bg='powderblue')

# Centering frame
center_frame = tk.Frame(root, bg='white')
center_frame.place(relx=0.5, rely=0.5, anchor='center')

# Title
title_label = tk.Label(center_frame, text="File Encryptor/Decryptor", font=('Times New Roman', 22, 'bold'), bg='powderblue', fg='black')
title_label.pack(pady=40)

# Encrypt Section
encrypt_label = tk.Label(center_frame, text="Encrypt a File", font=('Times New Roman', 18, 'bold'), bg='#ffffff', fg='#007bff')
encrypt_label.pack(pady=(20, 10))

encrypt_file_button = tk.Button(center_frame, text="Choose File", command=select_file_and_encrypt, font=('Times New Roman', 14), bg='#007bff', fg='#ffffff', width=20, highlightbackground="#000000", highlightthickness=1)
encrypt_file_button.pack(pady=(5, 10))

# Decrypt Section
decrypt_label = tk.Label(center_frame, text="Decrypt a File", font=('Times New Roman', 18, 'bold'), bg='#ffffff', fg='#007bff')
decrypt_label.pack(pady=(20, 10))

decrypt_file_button = tk.Button(center_frame, text="Choose File", command=select_file_and_decrypt, font=('Times New Roman', 14), bg='#007bff', fg='#ffffff', width=20, highlightbackground="#000000", highlightthickness=1)
decrypt_file_button.pack(pady=(5, 10))

# Run the GUI event loop
root.mainloop()
