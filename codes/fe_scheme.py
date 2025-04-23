import random, math

def is_prime(n, k=5):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(p):
            return p

def lcm(a, b):
    return a*b // math.gcd(a, b)

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a)*y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def keygen(bits=256):
    """
    Paillier key generation.
    Returns (public_key, private_key):
      public_key = (n, g)
      private_key = (lam, mu)
    """
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    n = p*q
    nsq = n*n
    g = n + 1
    lam = lcm(p-1, q-1)
    def L(u): return (u-1)//n
    mu = modinv(L(pow(g, lam, nsq)), n)
    return (n, g), (lam, mu)

def encrypt(m, public_key):
    """Paillier encrypt integer m under public_key."""
    n, g = public_key
    nsq = n*n
    if not (0 <= m < n):
        raise ValueError("Message out of range")
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    return (pow(g, m, nsq) * pow(r, n, nsq)) % nsq

def decrypt(c, private_key, public_key):
    """Paillier decrypt c under (private_key, public_key)."""
    n, g = public_key
    nsq = n*n
    lam, mu = private_key
    x = pow(c, lam, nsq)
    return ((x-1)//n * mu) % n

def aggregate(ciphertexts, public_key):
    """Homomorphic aggregation (multiplication) = encryption of sum."""
    n, _ = public_key
    nsq = n*n
    agg = 1
    for c in ciphertexts:
        agg = (agg * c) % nsq
    return agg
