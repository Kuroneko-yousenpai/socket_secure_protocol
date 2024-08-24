import io
import socket
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
    B_SYNC = 4294967296
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
    SIGNATURE = b'\xDE\xAD\xC0\xDE'

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

        int_size = struct.calcsize(">I")
        packet_length = len(self.SIGNATURE) + int_size + len(salt) + len(iv) + len(encryptor.tag) + len(encrypted_header)

        # Write salt, iv, tag, and encrypted header
        stream.seek(0)
        stream.write(self.SIGNATURE + struct.pack(">I", packet_length) + salt + iv + encryptor.tag + encrypted_header)

@dataclass
class TestStructure:
    test_id: int = 0
    test_uint_id: int = 0
    test_str: str = ""

class TestBinarySerializer:
    COMMAND_ID: int = 100001

    def serializeCommand(self, stream, s_data, pwd_key):
        header = AdvancedSecureCommandHeader()
        header.command_id = self.COMMAND_ID

        data = bytearray()
        data += struct.pack('>i', s_data["test_res"].test_id)
        data += struct.pack('>I', s_data["test_res"].test_uint_id)
        test_str_bytes = s_data["test_res"].test_str.encode('utf-8')
        data += struct.pack('>H', len(test_str_bytes))
        data += test_str_bytes
        header.length = len(data)
        print(f"Command ID: {header.command_id}")
        print(f"Length: {header.length}")
        stream.write(data)
        header.write(stream, pwd_key)

def serializeCommand(command_id, data, s_data=None, pwd_key=None):
    command_serializers = {TestBinarySerializer.COMMAND_ID: TestBinarySerializer()}
    serializer = command_serializers.get(command_id)
    if serializer is not None:
        return serializer.serializeCommand(data, s_data, pwd_key)
    return None

def client():
    try:
        with open('secure_password.bin', 'rb') as f:
            pwd_key = f.read()
    except FileNotFoundError:
        print("Error: File 'secure_password.bin' not found")
        return

    s_data = {"test_res": TestStructure(test_id=-13, test_uint_id=1337, test_str="Test")}
    print(f"{s_data}")
    s_stream = io.BytesIO(bytearray())
    serializeCommand(TestBinarySerializer.COMMAND_ID, s_stream, s_data, pwd_key)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))

    client.send(s_stream.getvalue())
    print("Data sended to server")
    client.close()


def main():
    client()


if __name__ == "__main__":
    main()