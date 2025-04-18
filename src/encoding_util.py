import random

def is_prime(n: int, k: int = 5) -> bool:
    """Перевірка простоти тестом Міллера–Рабіна"""
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Генеруємо випадкове просте число з вказаною бітовою довжиною"""
    while True:
        candidate = random.getrandbits(bits) | (1 << bits-1) | 1
        if is_prime(candidate):
            return candidate

def egcd(a: int, b: int) -> tuple[int,int,int]:
    """Розширений алгоритм Евкліда: повертає (g, x, y) такі, що a*x + b*y = g = gcd(a,b)"""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    """Обчислює обернене до a за модулем m: a * inv ≡ 1 (mod m)"""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('modinv does not exist')
    return x % m

def generate_keys(bits: int = 16) -> tuple[tuple[int,int], tuple[int,int]]:
    """Повертає e, d, n"""
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if egcd(e, phi)[0] != 1:
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2

    d = modinv(e, phi)
    return e, d, n
def encrypt(pubkey: tuple[int, int], plaintext: bytes) -> bytes:
    e, n = pubkey
    block_size = (n.bit_length() + 7) // 8
    max_plain_size = block_size - 1
    cipher_blocks = []

    for i in range(0, len(plaintext), max_plain_size):
        block = plaintext[i:i + max_plain_size]
        if len(block) < max_plain_size:
            block = b'\x00' + block
        num = int.from_bytes(block, byteorder='big')
        encrypted_num = pow(num, e, n)
        cipher_blocks.append(encrypted_num.to_bytes(block_size, byteorder='big'))

    return b''.join(cipher_blocks)

def decrypt(privkey: tuple[int, int], ciphertext: bytes) -> bytes:
    d, n = privkey
    block_size = (n.bit_length() + 7) // 8
    plain_blocks = []

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        num = int.from_bytes(block, byteorder='big')
        decrypted_num = pow(num, d, n)
        decrypted_bytes = decrypted_num.to_bytes(block_size, byteorder='big').lstrip(b'\x00')
        plain_blocks.append(decrypted_bytes)

    return b''.join(plain_blocks)
