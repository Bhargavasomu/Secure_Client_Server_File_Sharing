from math import (
    sqrt,
)
import random


def miller_rabin(n, k=10):
    if n == 2 or n == 3:
        return True

    # If number is even, it's a composite number
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_large_prime():
    """
    Take random numbers b/w 10^10 to 10^19 and do rabin miller's
    primality test on each of them.
    """
    while True:
        rand_num = random.randint(10**10, 10**19)
        if miller_rabin(rand_num):
            break

    return rand_num


# def get_primitive_root(prime):
#     """
#     Returns the least primitive root of the prime number
#     """
#     coprime_set = {num for num in range(1, prime) if gcd(num, prime) == 1}
#     primitive_roots = (
#         [g for g in range(1, prime)
#          if coprime_set == {pow(g, powers, prime)
#          for powers in range(1, prime)}
#          ]
#     )
#     return primitive_roots[random.randint(0, len(primitive_roots) - 1)]


def modularquickpow(x, y, z):
    """
    Fastly computes (x^y) % z
    """
    if y == 0:
        return 1
    if y == 1:
        return (x % z)

    halfpow = modularquickpow(x, y//2, z) % z
    if (y % 2) == 0:
        return (halfpow * halfpow) % z
    else:
        return (((halfpow * halfpow) % z) * (x % z)) % z


def find_prime_factors(n):
    while (n % 2) == 0:
        yield(2)
        n = n // 2

    # n must be odd at this point. So we can skip
    # one element (Note i = i +2)
    for i in range(3, int(sqrt(n)) + 1, 2):
        # While i divides n, print i and divide n
        while (n % i) == 0:
            yield(i)
            n = n // i

    # This condition is to handle the case when
    # n is a prime number greater than 2
    if n > 2:
        yield(n)


def get_least_primitive_root(p):
    """
    This function works based on the assumption that
    p is definitely a prime without further checking.
    """
    phi = p - 1
    phi_prime_factors = sorted(set(find_prime_factors(phi)))

    # Check for every number from 2 to phi
    for r in range(2, p):
        # Iterate through all prime factors of phi
        # and check if we found a power with value 1.
        flag = False
        for prime_factor in phi_prime_factors:
            # Check if r^((phi)/primefactors) mod n is 1 or not
            if modularquickpow(r, phi//prime_factor, p) == 1:
                flag = True
                break
        if flag is False:
            return r

    # If no primitive root found
    return -1


def gen_keys(g, prime):
    """
    Generates both the public and private key.
    Private Key has 9 digits.
    """
    priv_key = random.randint(10**10, 10**20)
    # The Public key is (g ^ x) % prime
    pub_key = modularquickpow(g, priv_key, prime)

    return pub_key, priv_key
