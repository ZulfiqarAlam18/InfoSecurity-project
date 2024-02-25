import getpass
import hashlib
import os
import sqlite3
from cryptography.fernet import Fernet

# Connect to the SQLite database
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

# Create users table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)''')

# Create passwords table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                  (username TEXT, encrypted_password TEXT, encryption_key TEXT,
                   FOREIGN KEY (username) REFERENCES users(username))''')

# Function to authenticate users
def authenticate(username, password):
    cursor.execute('SELECT password_hash, salt FROM users WHERE username=?', (username,))
    stored_data = cursor.fetchone()
    if stored_data is not None:
        stored_password_hash, salt = stored_data
        hashed_password = hash_password(password, salt)
        if stored_password_hash == hashed_password:
            return True
    return False

# Function to hash the password with salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    else:
        salt = bytes.fromhex(salt)  # Convert hex string salt back to bytes
    hash_object = hashlib.sha256()
    hash_object.update(salt)
    hash_object.update(password.encode())
    hashed_password = hash_object.hexdigest()
    return hashed_password, salt.hex()

# Function to encrypt a password
def encrypt_password(password):
    # Generate a Fernet key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    # Encrypt the password
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password.decode(), key.decode()

# Function to decrypt a password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    # Decrypt the password
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

# Function to add a new user
def add_user(username, password):
    hashed_password, salt = hash_password(password)
    cursor.execute('INSERT INTO users VALUES (?, ?, ?)', (username, hashed_password, salt))
    conn.commit()

# Function to add a new password
def add_password(username):
    new_password = getpass.getpass("Enter the new password: ")
    encrypted_password, key = encrypt_password(new_password)
    cursor.execute('INSERT INTO passwords VALUES (?, ?, ?)', (username, encrypted_password, key))
    conn.commit()
    print("Password added successfully!")

# Function to retrieve a password
def retrieve_password(username):
    cursor.execute('SELECT encrypted_password, encryption_key FROM passwords WHERE username=?', (username,))
    result = cursor.fetchone()
    if result:
        encrypted_password, key = result
        decrypted_password = decrypt_password(encrypted_password, key)
        print("Retrieved password:", decrypted_password)
    else:
        print("No password found for this user.")

# Function to retrieve all passwords for a user
def retrieve_all_passwords(username):
    cursor.execute('SELECT encrypted_password, encryption_key FROM passwords WHERE username=?', (username,))
    results = cursor.fetchall()
    if results:
        print("All passwords for", username + ":")
        for encrypted_password, key in results:
            decrypted_password = decrypt_password(encrypted_password, key)
            print("- ", decrypted_password)
    else:
        print("No passwords found for this user.")

# Main function to run the password manager
def main():
    print("Welcome to the Password Manager!")
    
    while True:
        print("\n1. Login")
        print("2. Register")
        print("3. Retrieve All Passwords")
        print("4. Exit")
        choice = input("Please select an option: ")
        
        if choice == "1":
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")
            
            if authenticate(username, password):
                print("Login successful!")
                # Once logged in, provide options to add, retrieve, or display all passwords
                while True:
                    print("\n1. Add Password")
                    print("2. Retrieve Password")
                    print("3. Retrieve All Passwords")
                    print("4. Logout")
                    option = input("Please select an option: ")
                    
                    if option == "1":
                        add_password(username)
                    elif option == "2":
                        retrieve_password(username)
                    elif option == "3":
                        retrieve_all_passwords(username)
                    elif option == "4":
                        print("Logged out.")
                        break
                    else:
                        print("Invalid option. Please try again.")
            else:
                print("Invalid username or password. Please try again.")
        elif choice == "2":
            username = input("Enter a new username: ")
            password = getpass.getpass("Enter a new password: ")
            add_user(username, password)
            print("User registered successfully!")
        elif choice == "3":
            username = input("Enter your username: ")
            retrieve_all_passwords(username)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
