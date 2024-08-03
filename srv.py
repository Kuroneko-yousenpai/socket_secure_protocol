import io
import socket
import threading
import time
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AdvancedSecureCommandHeader:
    MAX_UINT32 = 4294967295
    CONST_FLAGS = 87
    B_FLAG = 128
    B_SYNC = 32768
    D_FLAG = 32
    D_SYNC = 1073741824
    E_FLAG = 8
    E_SYNC = 2147483648
    CLEAN_COMMAND_ID = 4294967295
    CLEAN_LENGTH = 1073741823
    MAX_COMMAND_ID_VALUE = 4294967295
    MAX_LENGTH_VALUE = 1073741823
    ILLEGAL_COMMAND_HEADER = "Invalid command header"
    ILLEGAL_VAR_VALUES = "Invalid variable values"
    NONCE_SIZE = 12

    def __init__(self):
        self.is_valid = False
        self.command_id = 0
        self.length = 0
        self.flags = 0
        self.raw_command_id = 0
        self.raw_length = 0
        self.data = bytearray()

    def derive_key(self, pwd_key, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(pwd_key)

    def read(self, stream, pwd_key):
        try:
            self.fillRawsFromStream(stream, pwd_key)
            if self.validate():
                self.parse()
                return self
            raise ValueError(self.ILLEGAL_COMMAND_HEADER)
        except Exception as e:
            print(f"Read error: {str(e)}")
            raise

    def fillRawsFromStream(self, stream, pwd_key):
        header_length = 9
        timestamp_length = 8
        hmac_length = 32
        timestamp_end = header_length + timestamp_length
        hmac_end = timestamp_end + hmac_length
        salt = stream.read(16)
        nonce = stream.read(12)
        tag = stream.read(16)
        encrypted_header = stream.read()

        if len(salt) != 16:
            raise ValueError("Invalid salt length")
        elif len(nonce) != 12:
            raise ValueError("Invalid nonce length")
        elif len(tag) != 16:
            raise ValueError("Invalid tag length")
        if not encrypted_header:
            raise ValueError("Invalid encrypted header length")

        print(f"Server - Salt: {salt.hex()}")
        print(f"Server - Nonce: {nonce.hex()}")
        print(f"Server - Tag: {tag.hex()}")
        print(f"Server - Ciphertext: {encrypted_header.hex()}")

        key = self.derive_key(pwd_key, salt)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_header = decryptor.update(encrypted_header) + decryptor.finalize()

        print(f"Server - Decrypted Header: {decrypted_header.hex()}")
        print(f"Server - Header data: {decrypted_header[:header_length].hex()}")

        self.flags, self.raw_command_id, self.raw_length = struct.unpack(">BII", decrypted_header[:header_length])

        data_length = self.raw_length & self.CLEAN_LENGTH
        self.data = decrypted_header[header_length:header_length+data_length]
        print(f"Server - Data: {self.data.hex()}")
        timestamp = decrypted_header[header_length+data_length:data_length+timestamp_end]
        print(f"Server - Timestamp: {timestamp.hex()}")
        hmac_value = decrypted_header[data_length+timestamp_end:data_length+hmac_end]
        print(f"Server - HMAC: {hmac_value.hex()}")

        # Integrity check using HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        print(f"Before verify 0: {decrypted_header[:header_length].hex()}")
        h.update(decrypted_header[:header_length] + timestamp)
        print(f"Before verify 1: {hmac_value.hex()}")
        h.verify(hmac_value)

    def validate(self):
        self.is_valid = (
            self.check1() and
            self.checkE() and
            self.checkD() and
            self.checkB()
        )
        return self.is_valid

    def check1(self):
        return (self.flags & self.CONST_FLAGS) == self.CONST_FLAGS

    def checkE(self):
        return (self.flags & self.E_FLAG) != (self.raw_length & self.E_SYNC)

    def checkD(self):
        return (self.flags & self.D_FLAG) != (self.raw_length & self.D_SYNC)

    def checkB(self):
        return (self.flags & self.B_FLAG) != (self.raw_command_id & self.B_SYNC)

    def parse(self):
        self.command_id = self.raw_command_id & self.CLEAN_COMMAND_ID
        self.length = self.raw_length & self.CLEAN_LENGTH

    def write(self, stream, pwd_key):
        self.raw_command_id = self.command_id
        self.raw_length = self.length
        self.flags = self.CONST_FLAGS
        if os.urandom(1)[0] > 127:
            self.flags |= self.B_FLAG
        else:
            self.raw_command_id |= self.B_SYNC
        if os.urandom(1)[0] > 127:
            self.flags |= self.D_FLAG
        else:
            self.raw_length |= self.D_SYNC
        if os.urandom(1)[0] > 127:
            self.flags |= self.E_FLAG
        else:
            self.raw_length |= self.E_SYNC

        s_data = stream.getvalue()
        header_data = struct.pack(">BII", self.flags, self.raw_command_id, self.raw_length)
        timestamp = struct.pack(">Q", int(time.time()))

        # Generate salt
        salt = os.urandom(16)
        key = self.derive_key(pwd_key, salt)

        # Integrity check using HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(header_data + timestamp)
        hmac_value = h.finalize()

        iv = os.urandom(self.NONCE_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_header = encryptor.update(header_data + s_data + timestamp + hmac_value) + encryptor.finalize()

        # Debug prints
        print(f"Client - Salt: {salt.hex()}")
        print(f"Client - Nonce: {iv.hex()}")
        print(f"Client - Tag: {encryptor.tag.hex()}")
        print(f"Client - Ciphertext: {encrypted_header.hex()}")
        print(f"Client - Header data: {header_data.hex()}")
        print(f"Client - Client data: {s_data.hex()}")
        print(f"Client - HMAC: {hmac_value.hex()}")
        print(f"Client - Timestamp: {timestamp.hex()}")

        # Write salt, iv, tag, and encrypted header
        stream.seek(0)
        stream.write(salt + iv + encryptor.tag + encrypted_header)

@dataclass
class TestStructure:
    test_id: int = 0
    test_uint_id: int = 0
    test_str: str = ""

class TestSerializer:
    COMMAND_ID: int = 100001

    def deserializeCommand(self, command_data):
        test_req = TestStructure()
        stream = io.BytesIO(command_data)
        test_req.test_id = struct.unpack(">i", stream.read(4))[0]
        test_req.test_uint_id = struct.unpack(">I", stream.read(4))[0]
        test_str_length = struct.unpack('>H', stream.read(2))[0]
        test_req.test_str = struct.unpack(f">{test_str_length}s", stream.read(test_str_length))[0].decode("latin-1")

        return test_req

def deserializeCommand(command_data, header):
    command_serializers = {TestSerializer.COMMAND_ID: TestSerializer()}
    serializer = command_serializers.get(header.command_id)
    if serializer is not None:
        return serializer.deserializeCommand(command_data)
    return None

def handle_client(client_socket, password):
    try:
        req_data = client_socket.recv(1024)
        stream = io.BytesIO(req_data)
        header = AdvancedSecureCommandHeader()
        header.read(stream, password)
        print(f"Received command ID: {header.command_id}, Length: {header.length}")
        if header.length > 0:
            msg = deserializeCommand(header.data, header)
            if msg is not None:
                print(msg)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


def server():
    try:
        with open('secure_password.bin', 'rb') as f:
            pwd_key = f.read()
    except FileNotFoundError:
        print("Error: File 'secure_password.bin' not found")
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    print("Server listening on port 9999")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, pwd_key))
        client_handler.start()


def main():
    server()


if __name__ == "__main__":
    main()