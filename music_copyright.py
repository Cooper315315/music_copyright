import sqlite3
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import getpass
import base64
import bcrypt
import re

LOG_FILE = "access.log"
ADMIN_USERNAME = "admin1"
ADMIN_PASSWORD = bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt())

def validate_username(username):
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username) is not None

def validate_filename(filename):
    return re.match(r'^[a-zA-Z0-9_\-\.]{1,255}$', filename) is not None

def sanitize_filename(filename):
    return os.path.basename(filename)

def log_activity(activity, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - User: {username} - {activity}\n"
    with open(LOG_FILE, "a") as logfile:
        logfile.write(log_entry)

def encrypt(data, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt(encrypted_data, password):
    try:
        key = hashlib.sha256(password.encode()).digest()
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    except ValueError as e:
        print(f"Error decrypting data: {e}")
        return None

def create_tables():
    conn = sqlite3.connect('music_database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        content BLOB NOT NULL,
        checksum TEXT NOT NULL,
        created_at TEXT NOT NULL,
        modified_at TEXT
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audio_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        content BLOB NOT NULL,
        checksum TEXT NOT NULL,
        created_at TEXT NOT NULL,
        modified_at TEXT
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')
    cursor.execute('SELECT * FROM users WHERE username = ?', (ADMIN_USERNAME,))
    if not cursor.fetchone():
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                       (ADMIN_USERNAME, ADMIN_PASSWORD, 1))
    conn.commit()
    conn.close()

def register_user():
    username = input("Enter username: ")
    if not validate_username(username):
        print("Invalid username. Use 3-20 alphanumeric characters or underscores.")
        return
    password = getpass.getpass("Enter password: ")
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    conn = sqlite3.connect('music_database.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', (username, hashed_password, 0))
        conn.commit()
        log_activity(f"User {username} registered", username="System")
        print("User registered successfully.")
    except sqlite3.IntegrityError:
        print("Username already exists. Please choose a different username.")
    finally:
        conn.close()

def login_user():
    username = input("Enter username: ")
    conn = sqlite3.connect('music_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        password = getpass.getpass("Enter password: ")
        if bcrypt.checkpw(password.encode(), user[2]):
            log_activity(f"User {username} logged in", username=username)
            return user
        else:
            print("Invalid username or password.")
            return None
    else:
        print("Invalid username or password.")
        return None

def add_document(doc_path, password, username):
    try:
        filename = sanitize_filename(doc_path)
        if not validate_filename(filename):
            print("Invalid filename. Use alphanumeric characters, underscores, hyphens, or dots.")
            return
        with open(doc_path, 'rb') as file:
            content = file.read()
        encrypted_content = encrypt(content, password)
        checksum = hashlib.sha256(content).hexdigest()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO documents (name, content, checksum, created_at) VALUES (?, ?, ?, ?)',
                       (filename, encrypted_content, checksum, timestamp))
        conn.commit()
        conn.close()
        print("Document added successfully.")
        log_activity(f"Document {filename} added", username=username)
    except Exception as e:
        print(f"Error adding document: {e}")

def add_audio_file(audio_path, password, username):
    try:
        filename = sanitize_filename(audio_path)
        if not validate_filename(filename):
            print("Invalid filename. Use alphanumeric characters, underscores, hyphens, or dots.")
            return
        with open(audio_path, 'rb') as file:
            content = file.read()
        encrypted_content = encrypt(content, password)
        checksum = hashlib.sha256(content).hexdigest()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO audio_files (name, content, checksum, created_at) VALUES (?, ?, ?, ?)',
                       (filename, encrypted_content, checksum, timestamp))
        conn.commit()
        conn.close()
        print("Audio file added successfully.")
        log_activity(f"Audio file {filename} added", username=username)
    except Exception as e:
        print(f"Error adding audio file: {e}")

def retrieve_document(doc_id, password, username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name, content FROM documents WHERE id = ?', (doc_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            doc_name, encrypted_content = result
            decrypted_content = decrypt(encrypted_content, password)
            if decrypted_content is not None:
                with open(f'retrieved_{doc_name}', 'wb') as file:
                    file.write(decrypted_content)
                print("Document retrieved successfully.")
                log_activity(f"Document {doc_name} retrieved", username=username)
            else:
                print("Failed to decrypt document.")
        else:
            print("Document not found.")
    except Exception as e:
        print(f"Error retrieving document: {e}")

def retrieve_audio_file(audio_id, password, username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name, content FROM audio_files WHERE id = ?', (audio_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            audio_name, encrypted_content = result
            decrypted_content = decrypt(encrypted_content, password)
            if decrypted_content is not None:
                with open(f'retrieved_{audio_name}', 'wb') as file:
                    file.write(decrypted_content)
                print("Audio file retrieved successfully.")
                log_activity(f"Audio file {audio_name} retrieved", username=username)
            else:
                print("Failed to decrypt audio file.")
        else:
            print("Audio file not found.")
    except Exception as e:
        print(f"Error retrieving audio file: {e}")

def list_artifacts(username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM documents')
        documents = cursor.fetchall()
        cursor.execute('SELECT id, name FROM audio_files')
        audio_files = cursor.fetchall()
        conn.close()
        print("Documents:")
        for doc in documents:
            print(f"ID: {doc[0]}, Name: {doc[1]}")
        print("\nAudio Files:")
        for audio in audio_files:
            print(f"ID: {audio[0]}, Name: {audio[1]}")
        log_activity("Artifacts listed", username=username)
    except Exception as e:
        print(f"Error listing artifacts: {e}")

def update_document(doc_id, new_path, new_name, password, username):
    try:
        filename = sanitize_filename(new_name)
        if not validate_filename(filename):
            print("Invalid filename. Use alphanumeric characters, underscores, hyphens, or dots.")
            return
        with open(new_path, 'rb') as file:
            new_content = file.read()
        encrypted_content = encrypt(new_content, password)
        checksum = hashlib.sha256(new_content).hexdigest()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM documents WHERE id = ?', (doc_id,))
        old_name = cursor.fetchone()
        if old_name:
            old_name = old_name[0]
            cursor.execute('UPDATE documents SET name = ?, content = ?, checksum = ?, modified_at = ? WHERE id = ?',
                           (filename, encrypted_content, checksum, timestamp, doc_id))
            conn.commit()
            print("Document updated successfully.")
            log_activity(f"Document {old_name} updated to {filename}", username=username)
        else:
            print("Document not found.")
        conn.close()
    except Exception as e:
        print(f"Error updating document: {e}")

def update_audio_file(audio_id, new_path, new_name, password, username):
    try:
        filename = sanitize_filename(new_name)
        if not validate_filename(filename):
            print("Invalid filename. Use alphanumeric characters, underscores, hyphens, or dots.")
            return
        with open(new_path, 'rb') as file:
            new_content = file.read()
        encrypted_content = encrypt(new_content, password)
        checksum = hashlib.sha256(new_content).hexdigest()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM audio_files WHERE id = ?', (audio_id,))
        old_name = cursor.fetchone()
        if old_name:
            old_name = old_name[0]
            cursor.execute('UPDATE audio_files SET name = ?, content = ?, checksum = ?, modified_at = ? WHERE id = ?',
                           (filename, encrypted_content, checksum, timestamp, audio_id))
            conn.commit()
            print("Audio file updated successfully.")
            log_activity(f"Audio file {old_name} updated to {filename}", username=username)
        else:
            print("Audio file not found.")
        conn.close()
    except Exception as e:
        print(f"Error updating audio file: {e}")

def delete_document(doc_id, username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM documents WHERE id = ?', (doc_id,))
        doc_name = cursor.fetchone()
        if doc_name:
            doc_name = doc_name[0]
            cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            conn.commit()
            print("Document deleted successfully.")
            log_activity(f"Document {doc_name} deleted", username=username)
        else:
            print("Document not found.")
        conn.close()
    except Exception as e:
        print(f"Error deleting document: {e}")

def delete_audio_file(audio_id, username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM audio_files WHERE id = ?', (audio_id,))
        audio_name = cursor.fetchone()
        if audio_name:
            audio_name = audio_name[0]
            cursor.execute('DELETE FROM audio_files WHERE id = ?', (audio_id,))
            conn.commit()
            print("Audio file deleted successfully.")
            log_activity(f"Audio file {audio_name} deleted", username=username)
        else:
            print("Audio file not found.")
        conn.close()
    except Exception as e:
        print(f"Error deleting audio file: {e}")

def delete_user(username_to_delete, is_admin, username):
    if not is_admin:
        print("You do not have permission to delete users.")
        log_activity("Unauthorized attempt to delete user", username=username)
        return
    admin_password = getpass.getpass("Enter administrator password: ")
    if not bcrypt.checkpw(admin_password.encode(), ADMIN_PASSWORD):
        print("Incorrect administrator password.")
        log_activity("Failed attempt to delete user (incorrect admin password)", username=username)
        return
    if username_to_delete == ADMIN_USERNAME:
        print("Cannot delete the default administrator account.")
        return
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (username_to_delete,))
        if cursor.rowcount > 0:
            conn.commit()
            print(f"User {username_to_delete} deleted successfully.")
            log_activity(f"User {username_to_delete} deleted", username=username)
        else:
            print(f"User {username_to_delete} not found.")
        conn.close()
    except Exception as e:
        print(f"Error deleting user: {e}")

def modify_user(username_to_modify, is_admin, username):
    if not is_admin:
        print("You do not have permission to modify users.")
        log_activity("Unauthorized attempt to modify user", username=username)
        return
    admin_password = getpass.getpass("Enter administrator password: ")
    if not bcrypt.checkpw(admin_password.encode(), ADMIN_PASSWORD):
        print("Incorrect administrator password.")
        log_activity("Failed attempt to modify user (incorrect admin password)", username=username)
        return
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username_to_modify,))
        user = cursor.fetchone()
        if not user:
            print(f"User {username_to_modify} not found.")
            return
        user_id, current_username, current_password = user
        print(f"\nModifying User: {current_username}")
        new_username = input(f"Enter new username (leave blank to keep '{current_username}'): ") or current_username
        new_password = getpass.getpass(f"Enter new password (leave blank to keep current password): ")
        if new_password:
            new_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        else:
            new_password = current_password
        cursor.execute('''
            UPDATE users
            SET username = ?, password = ?
            WHERE id = ?
        ''', (new_username, new_password, user_id))
        conn.commit()
        conn.close()
        print(f"User {username_to_modify} modified successfully.")
        log_activity(f"User {username_to_modify} modified", username=username)
    except Exception as e:
        print(f"Error modifying user: {e}")

def manage_users(is_admin, username):
    if not is_admin:
        print("You do not have permission to manage users.")
        log_activity("Unauthorized attempt to manage users", username=username)
        return
    while True:
        print("\nUser Management:")
        print("1. List Users")
        print("2. Add User")
        print("3. Modify User")
        print("4. Delete User")
        print("5. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            list_users(username)
        elif choice == '2':
            register_user()
        elif choice == '3':
            username_to_modify = input("Enter username to modify: ")
            modify_user(username_to_modify, is_admin, username)
        elif choice == '4':
            username_to_delete = input("Enter username to delete: ")
            delete_user(username_to_delete, is_admin, username)
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")

def list_users(username):
    try:
        conn = sqlite3.connect('music_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, is_admin FROM users')
        users = cursor.fetchall()
        conn.close()
        print("\nUser List:")
        for user in users:
            print(f"Username: {user[0]}, Admin: {'Yes' if user[1] else 'No'}")
        log_activity("Listed users", username=username)
    except Exception as e:
        print(f"Error listing users: {e}")

def main():
    create_tables()
    while True:
        print("\nWelcome to the Music Copyright Management System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            user = login_user()
            if user:
                print(f"Login successful. Welcome, {user[1]}!")
                is_admin = user[3]
                username = user[1]

                while True:
                    print("\nMain Menu:")
                    print("1. Add Document")
                    print("2. Add Audio File")
                    print("3. Retrieve Document")
                    print("4. Retrieve Audio File")
                    print("5. List Artifacts")
                    print("6. Update Document")
                    print("7. Update Audio File")
                    print("8. Delete Document")
                    print("9. Delete Audio File")
                    if is_admin:
                        print("10. Manage Users")
                    print("11. Logout")

                    action = input("Enter your choice: ")

                    if action == '1':
                        doc_path = input("Enter document path: ")
                        password = getpass.getpass("Enter password to encrypt the document: ")
                        add_document(doc_path, password, username)
                    elif action == '2':
                        audio_path = input("Enter audio file path: ")
                        password = getpass.getpass("Enter password to encrypt the audio file: ")
                        add_audio_file(audio_path, password, username)
                    elif action == '3':
                        doc_id = input("Enter document ID to retrieve: ")
                        if doc_id.isdigit():
                            doc_id = int(doc_id)
                            password = getpass.getpass("Enter password to decrypt the document: ")
                            retrieve_document(doc_id, password, username)
                        else:
                            print("Invalid document ID. Please enter a number.")
                    elif action == '4':
                        audio_id = input("Enter audio file ID to retrieve: ")
                        if audio_id.isdigit():
                            audio_id = int(audio_id)
                            password = getpass.getpass("Enter password to decrypt the audio file: ")
                            retrieve_audio_file(audio_id, password, username)
                        else:
                            print("Invalid audio file ID. Please enter a number.")
                    elif action == '5':
                        list_artifacts(username)
                    elif action == '6':
                        doc_id = input("Enter document ID to update: ")
                        if doc_id.isdigit():
                            doc_id = int(doc_id)
                            new_path = input("Enter new document path: ")
                            new_name = input("Enter new document name: ")
                            password = getpass.getpass("Enter password to encrypt the new document: ")
                            update_document(doc_id, new_path, new_name, password, username)
                        else:
                            print("Invalid document ID. Please enter a number.")
                    elif action == '7':
                        audio_id = input("Enter audio file ID to update: ")
                        if audio_id.isdigit():
                            audio_id = int(audio_id)
                            new_path = input("Enter new audio file path: ")
                            new_name = input("Enter new audio file name: ")
                            password = getpass.getpass("Enter password to encrypt the new audio file: ")
                            update_audio_file(audio_id, new_path, new_name, password, username)
                        else:
                            print("Invalid audio file ID. Please enter a number.")
                    elif action == '8':
                        doc_id = input("Enter document ID to delete: ")
                        if doc_id.isdigit():
                            doc_id = int(doc_id)
                            delete_document(doc_id, username)
                        else:
                            print("Invalid document ID. Please enter a number.")
                    elif action == '9':
                        audio_id = input("Enter audio file ID to delete: ")
                        if audio_id.isdigit():
                            audio_id = int(audio_id)
                            delete_audio_file(audio_id, username)
                        else:
                            print("Invalid audio file ID. Please enter a number.")
                    elif action == '10' and is_admin:
                        manage_users(is_admin, username)
                    elif action == '11':
                        print("Logging out.")
                        break
                    else:
                        print("Invalid choice. Please try again.")
            else:
                print("Login failed.")
        elif choice == '3':
            print("Exiting the system.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
