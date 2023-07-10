import gmpy2
from time import time
from Crypto.Util.number import getPrime


def int_time():
    return int(round(time() * 1000))


class PrivateKey(object):
    def __init__(self, p, q, n):
        self.l = (p - 1) * (q - 1)  # lambda
        self.mu = gmpy2.invert(self.l, n)  # mu = 1/fi(n) mod n

    def __repr__(self):
        return '<CléPrivé: (%s,%s)>' % (self.l, self.mu)


class PublicKey(object):
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n  # n squared
        self.g = n + 1  # generator g

    def __repr__(self):
        return '<CléPublique: (%s)>' % self.n


def generate_keypair(bits):
    p = getPrime(bits)  # returns a random prime with a length = bits
    q = getPrime(bits)

    while (p == q):  # verifies that p != q
        p = getPrime(bits)
        q = getPrime(bits)

    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)  # returns to objects of type PrivateKey and PublicKey


def encrypt(pub, m):  # pub: the public key, m: the message
    zero = gmpy2.mpz(0)
    state = gmpy2.random_state(int_time())
    r = gmpy2.mpz_random(state, pub.n)  # generates a random number r between 0 and n-1

    while r == zero:  # verifying that r != 0
        r = gmpy2.mpz_random(state, pub.n)

    x = gmpy2.powmod(r, pub.n, pub.n_sq)  # x=r^n mod n^2
    y = gmpy2.powmod(pub.g, m, pub.n_sq)  # y=g^m mod n^2
    c = gmpy2.f_mod(gmpy2.mul(y, x), pub.n_sq)  # c = y*x mod n^2
    return c  # returns the cipher text


def decrypt(priv, pub, c):
    one = gmpy2.mpz(1)  # 1 of type mpz
    x = gmpy2.sub(gmpy2.powmod(c, priv.l, pub.n_sq), one)  # c^l - 1
    y = gmpy2.f_div(x, pub.n)  # (c^l - 1)/n  i.e  L(c^l)
    z = gmpy2.mul(y, priv.mu)  # L(c^l)*mu

    m = gmpy2.f_mod(z, pub.n)

    return m


def add_m(a, b):  # the sum of two messages (a+b must be less than n)
    return gmpy2.add(a, b)  # a+b mod n


def mul_c(pub, a, b):  # the multiplication of two cipher texts
    return gmpy2.f_mod(gmpy2.mul(a, b), pub.n_sq)  # a*b mod n^2


priv, pub = generate_keypair(40)  # generating the private and public key objects

print(repr(priv))  # output the private key
print(repr(pub))  # output the public key
print('')

m1 = 70790604053396213
m2 = 11995564545564541

a = add_m(pub,m1,m2) # a = E(m1+m2)
b = decrypt(priv,pub,mul_c(pub, encrypt(pub,m1), encrypt(pub,m2))) # b = D(E(m1)*E(m2))

print("a = ", a)
print("b = ", b)
print("OK" if a==b else "Not OK")
