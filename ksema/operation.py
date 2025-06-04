import base64
import json
import struct
from .object import *
from tlslite import *

def get_return_code_message(code):
    return mapRetCodeToString.get(code, "Unknown return")

def operation_ping(session_id, server_ip):
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "PING"
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return ping request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return True

def operation_encrypt(session_id, server_ip, plain_text: bytes, key_label: str) -> bytes:
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "ENCRYPT",
        "Label": key_label,
        "Data": base64.b64encode(plain_text).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return encrypt request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return base64.b64decode(res["data"]["message"])

def operation_decrypt(session_id, server_ip, cipher_text: bytes, key_label: str) -> bytes:
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "DECRYPT",
        "Label": key_label,
        "Data": base64.b64encode(cipher_text).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return decrypt request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    return base64.b64decode(res["data"]["message"])

def operation_sign(session_id, server_ip, data: bytes, key_label: str) -> bytes:
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "SIGN",
        "Label": key_label,
        "Data": base64.b64encode(data).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return sign request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    return base64.b64decode(res["data"]["message"])

def operation_verify(session_id, server_ip, data: bytes, signature: bytes, key_label: str):
    url = f"https://{server_ip}/api/hsm/request"
    data_len = len(data)
    sig_len = len(signature)
    data_payload = struct.pack(">H", data_len) + data + struct.pack(">H", sig_len) + signature
    payload = {
        "SessionID": session_id,
        "Operation": "VERIFY",
        "Label": key_label,
        "Data": base64.b64encode(data_payload).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return True

def operation_rng(session_id, server_ip, data: bytes) -> bytes:
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "RNG",
        "Data": base64.b64encode(data).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    return base64.b64decode(res["data"]["message"])

def operation_backup(session_id, server_ip, user_type, file_path: bytes, key_label: str):
    url = f"https://{server_ip}/api/hsm/request"

    payload = {
        "SessionID": session_id,
        "Operation": "BACKUP",
        "Label": key_label,
        "Data": base64.b64encode(file_path).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    try :
        res = json.loads(body.decode())
    except json.JSONDecodeError :
        dechuncked = dechunk_http_body(body)
        res = json.loads(dechuncked.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    data_backup = base64.b64decode(res["data"]["message"])

    header_len = struct.unpack(">H", data_backup[:2])[0]
    header = data_backup[2:2+header_len].decode()

    exported_len = struct.unpack(">H", data_backup[2+header_len:4+header_len])[0]
    exported = data_backup[4+header_len:4+header_len+exported_len].decode()

    with open(file_path.decode(), "w") as f:
        f.write(header + "\n" + exported)

    if user_type == USER_OBJECT:
        start = 4 + header_len + exported_len
        exported_len2 = struct.unpack(">H", data_backup[start:start+2])[0]
        exported2 = data_backup[start+2:start+2+exported_len2].decode()
        with open("priv"+file_path.decode(), "w") as f:
            f.write(header + "\n" + exported2)

    return True

def operation_restore(session_id, server_ip, file_path: str):
    with open(file_path, "rb") as f:
        lines = f.read()
    parts = lines.split(b"\n", 1)
    if len(parts) < 2:
        raise Exception("invalid backup file format")
    line = parts[1]

    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "RESTORE",
        "Data": line.decode() 
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    return True

def operation_delete(session_id, server_ip, key_label: str):
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "DELETE",
        "Label": key_label
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))

    return True

def operation_gen_key_sym(session_id, server_ip, key_label: str):
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "GENKEYSYM",
        "Label": key_label
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return True

def operation_gen_key_asym(session_id, server_ip, pub_label: str, priv_label: str):
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "GENKEYASYM",
        "Label": f"{pub_label};{priv_label}"
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return True

def operation_set_iv(session_id, server_ip, data: bytes):
    url = f"https://{server_ip}/api/hsm/request"
    payload = {
        "SessionID": session_id,
        "Operation": "SETIV",
        "Data": base64.b64encode(data).decode()
    }
    json_data = json.dumps(payload)
    content_length = len(json_data)

    sock = socket.create_connection((server_ip, 443))

    settings = HandshakeSettings()
    settings.keyShares = ["x25519mlkem768"]

    tls_conn = TLSConnection(sock)
    tls_conn.handshakeClientCert()

    request = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {server_ip}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{json_data}"
    )

    tls_conn.write(request.encode())

    response = b""
    while True:
        chunk = tls_conn.read(4096)
        if not chunk:
            break
        response += chunk

    tls_conn.close()

    header_data, _, body = response.partition(b"\r\n\r\n")
    status_line = header_data.split(b"\r\n")[0]
    status_code = int(status_line.split()[1])

    if status_code != 200:
        return False

    res = json.loads(body.decode())
    if not res.get("success", False):
        error_msg = res.get("ErrorMsg") or "return verify request is false"
        raise Exception(error_msg)
    if res["data"]["retCode"] != SUCCESS:
        raise Exception(get_return_code_message(res["data"]["retCode"]))
    
    return True


def uint16_to_bytes(num: int) -> bytes:
    return struct.pack('>H', num)

def dechunk_http_body(raw: bytes) -> bytes:
    out = b""
    while raw:
        i = raw.find(b"\r\n")
        if i == -1:
            break
        chunk_size = int(raw[:i], 16)
        raw = raw[i+2:]
        out += raw[:chunk_size]
        raw = raw[chunk_size+2:]
    return out