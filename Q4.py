from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

ip = 'localhost'
port = 5000
# ip = '172.26.201.17'
# port = 2134
io = remote(ip, port)
print("Connected to the server")

data1 = io.recvline().decode("utf-8")
print(data1)

io.sendline(str(4).encode())

data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)

pem_data = io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8") 
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
pem_data += io.recvline().decode("utf-8")
print(pem_data)
rsa_key = RSA.import_key(pem_data)
print("rsa key",rsa_key)
#we have prime we can find q
#we have n e p q we can find d
n = rsa_key.n
e = rsa_key.e
print("n", rsa_key.n)
print("e",rsa_key.e)

# print(rsa_key.p)
# print(rsa_key.d)

data1 = io.recvline().decode("utf-8")
print(data1)
data1 = io.recvline().decode("utf-8")
print(data1)

data1 = io.recvline().decode("utf-8")
print(data1)
intercepted_msg = io.recvline().decode("utf-8")
print("intercepted_msg", intercepted_msg)

data1 = io.recvline().decode("utf-8")
print(data1)

rsa_factor = io.recvline().decode("utf-8")
rsa_factor = rsa_factor.split("factor")[1][1:-1][2:]
rsa_factor = int(rsa_factor, 16)


#n = pq
q = rsa_factor
print("q", q)
p = n // q 
print("p", p)
phi_n = (p - 1) * (q - 1)
d = inverse(e, phi_n)
print("Private exponent (d):", d)

io.recvline().decode("utf-8")

intercepted_msg_bytes = bytes.fromhex(intercepted_msg[2:])

private_key = RSA.construct((n, e, d))
cipher = PKCS1_OAEP.new(private_key)

decrypted_msg = cipher.decrypt(intercepted_msg_bytes)

print("Decrypted message:", decrypted_msg.decode())

io.close()