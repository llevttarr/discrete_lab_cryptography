import socket
import threading
import src.encoding_util as enc_util
import src.hash_util as hash_util
import json
import base64

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())
        # create key pairs
        self.public_key,self.private_key,self.n = enc_util.generate_keys()

        # exchange public keys
        self.server_public_key = int(self.s.recv(1024))
        self.server_n = int(self.s.recv(1024))
        msg = f"{self.public_key}"
        self.s.send(msg.encode())
        msg = f"{self.n}"
        self.s.send(msg.encode())

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            data = self.s.recv(1024)
            try:
                data = json.loads(data.decode())
                message, m_hash = data["msg"], data["hash"]
                message = base64.b64decode(message)
                message = enc_util.decrypt((self.private_key, self.n),message).decode()
                if hash_util.verify(message, m_hash):
                    print(message)
                else:
                    print("err: hash mismatch")
            except Exception:
                print("err while decoding message")

    def write_handler(self):
        while True:
            message = input()
            m_hash = hash_util.get_hash(message)
            e_message = enc_util.encrypt((self.server_public_key, self.server_n), message.encode())
            res = {
                "msg":base64.b64encode(e_message).decode(),
                "hash": m_hash
            }
            self.s.send(json.dumps(res).encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
