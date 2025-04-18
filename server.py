import socket
import threading
import src.encoding_util as enc_util
import src.hash_util as hash_util
import random as r
import json
import base64

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.c_pub_keys = []
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.public_key, self.private_key, self.n = enc_util.generate_keys()
        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client
            msg = f"{self.public_key}"
            c.send(msg.encode())
            msg = f"{self.n}"
            c.send(msg.encode())
            c_pub_key = c.recv(1024).decode()
            n = c.recv(1024).decode()
            self.c_pub_keys.append( (int(c_pub_key),int(n)) )

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        m_hash = hash_util.get_hash(msg)
        for i,client in enumerate(self.clients):
            message = enc_util.encrypt(self.c_pub_keys[i],msg.encode())
            res = {
                "msg":base64.b64encode(message).decode(),
                "hash": m_hash
            }
            client.send(json.dumps(res).encode())

    def handle_client(self, c: socket, addr):
        while True:
            data = c.recv(1024)
            data = json.loads(data.decode())
            message, m_hash = data["msg"], data["hash"]
            message = base64.b64decode(message)
            message = enc_util.decrypt((self.private_key, self.n),message)
            for i,client in enumerate(self.clients):
                if client == c:
                    continue
                key, n = self.c_pub_keys[i]
                final_msg = enc_util.encrypt((key,n),message)
                res = {
                    "msg":base64.b64encode(final_msg).decode(),
                    "hash": m_hash
                }
                client.send(json.dumps(res).encode())

if __name__ == "__main__":
    s = Server(9001)
    s.start()
