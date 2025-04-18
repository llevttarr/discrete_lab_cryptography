# Дискретна Математика II - Лабораторна робота з теми "Криптографія"
## Розподіл на завдання:
> - Тарас Левицький - Message integrity, взаємодія клієнту й серверу
> - Максим Мацелюх - RSA (генерація ключів, encrypting, decrypting)
## Імплементація
При ініціалізації сервер генерує публічний та приватний ключі (e, d, n - про це детальніше в розділі RSA). 
```
def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.public_key, self.private_key, self.n = enc_util.generate_keys()
```
Клієнт при приєднанні до серверу також генерує свої ключі, а також обмінюється з сервером публічними ключами.
>client.py (Client.init_connection())
```
self.public_key,self.private_key,self.n = enc_util.generate_keys()

        # exchange public keys
        self.server_public_key = int(self.s.recv(1024))
        self.server_n = int(self.s.recv(1024))
        msg = f"{self.public_key}"
        self.s.send(msg.encode())
        msg = f"{self.n}"
        self.s.send(msg.encode())
```
>server.py (Server.start())
```
msg = f"{self.public_key}"
            c.send(msg.encode())
            msg = f"{self.n}"
            c.send(msg.encode())
            c_pub_key = c.recv(1024).decode()
            n = c.recv(1024).decode()
            self.c_pub_keys.append( (int(c_pub_key),int(n)) )
```
При надсиланні повідомлення з клієнту відбувається такий алгоритм дій:
- Клієнт кодує повідомлення публічним серверним ключем й надсилає на сервер повідомлення разом з хешем (для перевірки цілісності повідомлення)
- Сервер отримує й розкодовує повідомлення своїм приватним ключем, й надсилає всім іншим клієнтам використовуючи їхні публічні ключі
- Клієнти отримують повідомлення й розкодовують своїми приватними ключами, та перевіряють хеш, якщо він не співпадає - повідомлення було зміненим під час передачі, отже вже не дійсне
> При передачі байтів складно зрозуміти, де закінчується повідомлення, а де починається хеш. Для цього використовуються json та base64. 
### RSA
