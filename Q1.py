from Crypto.Hash import SHA256
from pwn import *
import json
from Crypto.Cipher import AES

ip = 'localhost'
port = 5000
io = remote(ip, port)
print("Connected to the server")

def share_key_to_AES_key(share_key):
    return SHA256.new(share_key.to_bytes(share_key.bit_length(), byteorder='big')).digest()

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

data1 = io.recvline().decode("utf-8")
print(data1)
io.sendline(str(1).encode())
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
prime = io.recvline().decode("utf-8")
print(prime)
prime = prime.split(":")[1][1:-1]
prime = int(prime)
print(prime)

gen = find_generator(prime)
print("Generator is : ", gen)

io.sendline(str(gen).encode())
data1 = io.recvline().decode("utf-8")
print(data1)

server_Pk = io.recvline().decode("utf-8")
print(server_Pk)
server_Pk = server_Pk.split(":")[1][1:-1]
server_Pk = int(server_Pk)
print(server_Pk)


myPrivateKey = random.randrange(start = 1,stop = prime-1)
myPublicKey = pow(gen, myPrivateKey, prime)



myShareKey = pow(server_Pk, myPrivateKey, prime)

io.sendline(str(myPublicKey))
data1 = io.recvline().decode("utf-8")
print(data1)

data1 = io.recvline().decode("utf-8")
print(data1)

data1 = io.recvline().decode("utf-8")
print(data1)

json_output = io.recvline().decode("utf-8")
print(json_output)


decoded_output = json.loads(json_output)
nonce = base64.b64decode(decoded_output['nonce'])
print("nonce", nonce)
header = base64.b64decode(decoded_output['header'])
print("header", header)
ciphertext = base64.b64decode(decoded_output['ciphertext'])
print("ciphertext", ciphertext)
tag = base64.b64decode(decoded_output['tag'])
print("tag", tag)

encryption_key = share_key_to_AES_key(myShareKey)

cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
cipher.update(header)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)



print("Decryption successful!")
print("Plaintext:", plaintext.decode('utf-8')) 

    
io.close()