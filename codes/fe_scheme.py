# fe_scheme.py
#
# A minimal implementation of Paillier homomorphic encryption primitives,
# including key generation, encryption, decryption, and homomorphic sum.

import random
import math

def is_prime(n, k=5):
    """
    Miller–Rabin primality test.
    - n: integer to test
    - k: number of accuracy rounds
    Returns True if n is (probably) prime, False otherwise.
    """
    if n < 2:
        return False
    # Quick check for small prime divisors
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    # Write n-1 as 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    # k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """
    Generate a random prime of specified bit-length.
    - bits: number of bits for the prime
    Loops until it finds a prime.
    """
    while True:
        # Ensure top bit and low bit set so that number has correct size and is odd
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def lcm(a, b):
    """Compute least common multiple of a and b."""
    return a * b // math.gcd(a, b)

def egcd(a, b):
    """
    Extended Euclidean algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    """
    Modular inverse: find x such that (a * x) % m == 1.
    Raises if inverse does not exist.
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def keygen(bits=256):
    """
    Generate Paillier keypair.
    - bits: total bit-length of modulus n (default 256)
    Returns (public_key, private_key), where
      public_key  = (n, g)
      private_key = (lam, mu)
    """
    # 1. Pick two large primes p, q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    nsq = n * n
    g = n + 1

    # 2. λ = lcm(p-1, q-1)
    lam = lcm(p - 1, q - 1)

    # 3. Precompute μ = (L(g^λ mod n^2))^{-1} mod n
    def L(u): return (u - 1) // n
    mu = modinv(L(pow(g, lam, nsq)), n)

    return (n, g), (lam, mu)

def encrypt(m, public_key):
    """
    Paillier encrypt integer m under public_key = (n, g).
    Encryption: c = g^m * r^n mod n^2, for random r ∈ [1, n), gcd(r,n)=1.
    """
    n, g = public_key
    nsq = n * n

    # m mod n (message space is Z_n)
    m_mod = int(m) % n

    # pick random r coprime with n
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break

    # compute ciphertext
    return (pow(g, m_mod, nsq) * pow(r, n, nsq)) % nsq

def decrypt(c, private_key, public_key):
    """
    Paillier decrypt ciphertext c using private_key = (lam, mu) and public_key = (n, g).
    Decryption: m = L(c^λ mod n^2) * μ mod n.
    Returns decrypted integer in [0, n).
    """
    n, g = public_key
    nsq = n * n
    lam, mu = private_key

    # compute u = c^λ mod n^2, then L(u)
    x = pow(c, lam, nsq)
    return ((x - 1) // n * mu) % n

def aggregate(ciphertexts, public_key):
    """
    Homomorphically aggregate multiple ciphertexts (product mod n^2)
    to get encryption of the sum of their plaintexts.
    Usage: given [c1, c2, ...], return c1 * c2 * ... mod n^2.
    """
    n, _ = public_key
    nsq = n * n
    agg = 1
    for c in ciphertexts:
        agg = (agg * c) % nsq
    return agg
