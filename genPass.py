import getpass
import hashlib

# Dummy database to store user credentials and passwords (replace with database integration later)
users = {
    "user1": {
        "password": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # Hashed password for "password1"
        "passwords": []  # List to store hashed passwords
    },
    "user2": {
        "password": "b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3",  # Hashed password for "password2"
        "passwords": []
    }
}

# Function to authenticate users
def authenticate(username, password):
    if username in users and users[username]["password"] == hash_password(password):
        return True
    return False

# Function to hash the password
def hash_password(password):
    # Use a secure hash function like SHA-1 (for simplicity, replace with stronger hashing algorithm in production)
    hash_object = hashlib.sha1(password.encode())
    hashed_password = hash_object.hexdigest()
    return hashed_password

# Function to add a new password
def add_password(username):
    new_password = getpass.getpass("Enter the new password: ")
    hashed_password = hash_password(new_password)
    users[username]["passwords"].append(hashed_password)
    print("Password added successfully!")

# Function to retrieve a password
def retrieve_password(username):
    # Implement password retrieval logic here
    pass

# Main function to run the password manager
def main():
    print("Welcome to the Password Manager!")
    
    while True:
        print("\n1. Login")
        print("2. Exit")
        choice = input("Please select an option: ")
        
        if choice == "1":
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")
            
            if authenticate(username, password):
                print("Login successful!")
                # Once logged in, provide options to add or retrieve passwords
                while True:
                    print("\n1. Add Password")
                    print("2. Retrieve Password")
                    print("3. Logout")
                    option = input("Please select an option: ")
                    
                    if option == "1":
                        add_password(username)
                    elif option == "2":
                        retrieve_password(username)
                    elif option == "3":
                        print("Logged out.")
                        break
                    else:
                        print("Invalid option. Please try again.")
            else:
                print("Invalid username or password. Please try again.")
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
