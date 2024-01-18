from cryptography.fernet import Fernet, InvalidToken

def generate_key():
    return Fernet.generate_key()

def save_key(key, key_file, password):
    cipher_suite = Fernet(key)
    encrypted_key = cipher_suite.encrypt(password)

    with open(key_file, 'wb') as file:
        file.write(encrypted_key)

def load_key(key_file, password):
    with open(key_file, 'rb') as file:
        encrypted_key = file.read()

    cipher_suite = Fernet(password)

    try:
        key = cipher_suite.decrypt(encrypted_key)
        return key
    except InvalidToken:
        print("Invalid password or corrupted key file.")
        return None

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        data = file.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

# Example usage:
password = b'SecurePassword123'  # Replace with your desired password
key = generate_key()  # Generating Fernet key directly

key_file = 'encryption_key.key'
save_key(key, key_file, password)

input_file = r'C:\Users\HP\Documents\MINI_PROJECT\MUSKAAN_B1\plain_text.txt'
encrypted_file = 'encrypted_file.txt'
decrypted_file = 'decrypted_file.txt'

encrypt_file(input_file, encrypted_file, key)
print("File plain.txt encrypted to {}".format(encrypted_file))

loaded_key = load_key(key_file, password)
if loaded_key:
    decrypt_file(encrypted_file, decrypted_file, loaded_key)
    print("File {} decrypted to {}".format(encrypted_file, decrypted_file))


