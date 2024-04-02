from Crypto.Hash import SHA256
from pwn import *
import json
from Crypto.Cipher import AES

ip = 'localhost'
port = 5000
io = remote(ip, port)

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
io.sendline(str(2).encode())
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
prime = io.recvline().decode("utf-8").split()[1]
prime = int(prime[2:],16)
print(prime)

gen = io.recvline().decode("utf-8").split()[1]
gen = int(gen[2:])
print(gen)
myPrivateKey = random.randrange(start = 1,stop = prime-1)
myPublicKey = pow(gen, myPrivateKey, prime)
io.sendline(str(myPublicKey).encode())
Server_publicKey = io.recvline().decode("utf-8").split()[-1]
Server_publicKey = int(Server_publicKey[2:],16)
print(Server_publicKey)
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
myShareKey = pow(Server_publicKey, myPrivateKey, prime)

encryption_key = share_key_to_AES_key(myShareKey)
cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
cipher.update(header)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)


print("Decryption successful!")
print("Plaintext:", plaintext.decode('utf-8')) 
    
io.close()