# fe_scheme.py
import random, math

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number of specified bit-length."""
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def lcm(a, b):
    return a * b // math.gcd(a, b)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Compute the modular inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def keygen(bits=256):
    """
    Generate a Paillier key pair.
    For demo purposes, we use a small key size; for production, use at least 2048 bits.
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    nsq = n * n
    g = n + 1  # common choice for Paillier
    lam = lcm(p - 1, q - 1)
    def L(u):
        return (u - 1) // n
    x = pow(g, lam, nsq)
    mu = modinv(L(x), n)
    public_key = (n, g)
    private_key = (lam, mu)
    return public_key, private_key

def encrypt(m, public_key):
    """Encrypt an integer m using Paillier encryption."""
    n, g = public_key
    nsq = n * n
    if m < 0 or m >= n:
        raise ValueError("Message out of range")
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def decrypt(c, private_key, public_key):
    """Decrypt a ciphertext c using Paillier decryption."""
    n, g = public_key
    nsq = n * n
    lam, mu = private_key
    x = pow(c, lam, nsq)
    Lx = (x - 1) // n
    m = (Lx * mu) % n
    return m

def aggregate(ciphertexts, public_key):
    """
    Aggregate a list of ciphertexts by multiplying them modulo n^2.
    (In Paillier, this yields an encryption of the sum of plaintexts.)
    """
    n, _ = public_key
    nsq = n * n
    agg = 1
    for c in ciphertexts:
        agg = (agg * c) % nsq
    return agg
