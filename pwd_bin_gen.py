import os


def generate_sec_bin(file_path, length=32):
    password = os.urandom(length)
    with open(file_path, 'wb') as f:
        f.write(password)
    print(f"File secure_password.bin generated and saved to {file_path}")

if __name__ == "__main__":
    generate_sec_bin('secure_password.bin')