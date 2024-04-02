import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pwn import *

ip = 'localhost'
port = 5000

io = remote(ip, port)


def is_generator(g, p):
    group_elements = set()
    for k in range(1, p):
        group_elements.add(pow(g, k, p))
    return len(group_elements) == p - 1 

def find_generator(p):
    for g in range(2, p):
        print("round :",g)
        if is_generator(g, p):
            return g
    return None

def share_key_to_AES_key(share_key):
    return SHA256.new(share_key).digest()

data1 = io.recvline().decode("utf-8")
io.sendline(str(1).encode())
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
data1 = io.recvline().decode("utf-8")
prime = io.recvline().decode("utf-8").split()[1]
prime = int(prime)
print(prime)
gen = find_generator(prime)
print("generator is ", gen)
io.sendline(str(gen))
data1 = io.recvline().decode("utf-8")
print(data1)
PK = io.recvline().decode("utf-8").split()[3]
PK = int(PK)
print(PK)
public_key  = prime -1000
# gen2 = find_generator(public_key)
io.sendline(str(public_key))
data1 = io.recvline().decode("utf-8")
print("asdfasdf",data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data = io.recvline().decode("utf-8")

print(data)

json_output = data
decoded_output = json.loads(json_output)
nonce = base64.b64decode(decoded_output['nonce'])
print("nonce", nonce)
header = base64.b64decode(decoded_output['header'])
print("header", header)
ciphertext = base64.b64decode(decoded_output['ciphertext'])
print("ciphertext", ciphertext)
tag = base64.b64decode(decoded_output['tag'])
print("tag", tag)

myPk = prime-1000
def find_share_key(public_key,PK,prime):
    share_key = pow(public_key,PK,prime)
    return SHA256.new(share_key.to_bytes(share_key.bit_length(),byteorder='big')).digest()
nonce = base64.b64decode(decoded_output['nonce'])
ciphertext = base64.b64decode(decoded_output['ciphertext'])
tag = base64.b64decode(decoded_output['tag'])

share_key = find_share_key(myPk, PK, prime)

key = share_key_to_AES_key(share_key)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    print("Decryption successful:")
    print("Flag:", plaintext.decode('utf-8'))
except ValueError as e:
    print("Decryption failed:", e)

io.close()
