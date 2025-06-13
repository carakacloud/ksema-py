import json
from .object import *
from .operation import *
from tlslite import *

class Ksema:
    def __init__(self, server_ip: str, api_key: str, pin: str):
        self.server_ip = server_ip
        self.api_key = api_key
        self.pin = pin
        self.sess_id = None
        self.user_type = None

        if not self.auth():
            raise Exception("Authentication failed")

    def auth(self) -> bool:
        payload = {
            "APIKey": self.api_key,
            "PIN": self.pin,
        }
        json_data = json.dumps(payload)
        content_length = len(json_data)

        # Open a socket
        sock = socket.create_connection((self.server_ip, 443))

        settings = HandshakeSettings()
        settings.keyShares = ["x25519mlkem768"]

        # Wrap socket in TLS
        tls_conn = TLSConnection(sock)
        tls_conn.handshakeClientCert()

        # Create raw HTTP POST request
        request = (
            f"POST /api/hsm/auth HTTP/1.1\r\n"
            f"Host: {self.server_ip}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {content_length}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{json_data}"
        )

        tls_conn.write(request.encode())

        # Read full response
        response = b""
        while True:
            chunk = tls_conn.read(4096)
            if not chunk:
                break
            response += chunk

        tls_conn.close()

        # Parse HTTP response
        header_data, _, body = response.partition(b"\r\n\r\n")
        status_line = header_data.split(b"\r\n")[0]
        status_code = int(status_line.split()[1])

        if status_code != 200:
            return False

        res = json.loads(body.decode())
        if not res.get("success", False):
            return False

        data = res.get("data", {})
        self.sess_id = data.get("sessionId")
        self.user_type = data.get("userType")

        return True

    def ping(self):
        return operation_ping(self.sess_id, self.server_ip)

    def encrypt(self, data: bytes, key_label: str) -> bytes:
        if self.user_type > USER_OBJECT and not key_label:
            raise ValueError("No key label specified")
        return operation_encrypt(self.sess_id, self.server_ip, data, key_label)

    def decrypt(self, data: bytes, key_label: str) -> bytes:
        if self.user_type > USER_OBJECT and not key_label:
            raise ValueError("No key label specified")
        return operation_decrypt(self.sess_id, self.server_ip, data, key_label)

    def sign(self, data: bytes, key_label: str) -> bytes:
        if self.user_type > USER_OBJECT and not key_label:
            raise ValueError("No key label specified")
        return operation_sign(self.sess_id, self.server_ip, data, key_label)

    def verify(self, data: bytes, signature: bytes, key_label: str) -> None:
        if self.user_type > USER_OBJECT and not key_label:
            raise ValueError("No key label specified")
        return operation_verify(self.sess_id, self.server_ip, data, signature, key_label)

    def rng(self, len_random=32) -> bytes:
        return operation_rng(self.sess_id, self.server_ip, uint16_to_bytes(len_random))
    
    def backup(self, filename: str, key_label: str) -> None:
        if self.user_type > USER_OBJECT and not key_label:
            raise ValueError("No key label specified")
        return operation_backup(self.sess_id, self.server_ip, self.user_type, filename.encode(), key_label)
    
    def restore(self, filename: str) -> None:
        return operation_restore(self.sess_id, self.server_ip, filename)
    
    def delete(self, key_label: str) -> None:
        return operation_delete(self.sess_id, self.server_ip, key_label)
    
    def keygen(self, key_label1: str, key_label2="") -> None:
        if key_label1 == "" :
            raise ValueError("Invalid key label")

        if key_label2 == "" :
            return operation_gen_key_sym(self.sess_id, self.server_ip, key_label1)
        else :
            return operation_gen_key_asym(self.sess_id, self.server_ip, key_label1, key_label2)
        
    def set_iv(self, iv: str) -> None:
        if len(iv) != 16 :
            raise ValueError("Invalid iv value, must be 16 chars")
        
        return operation_set_iv(self.sess_id, self.server_ip, iv.encode())