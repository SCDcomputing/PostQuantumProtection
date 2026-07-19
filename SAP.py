import math
import random
import sys

def quantum_order_finding(a, N):
    """
    Classical simulation of quantum order-finding subroutine.
    In a real quantum computer, this would use quantum phase estimation.
    This classical version uses trial to approximate the order.
    """
    for r in range(1, N):
        if pow(a, r, N) == 1:
            return r
    return None

def shors_algorithm(N):
    """
    Classical simulation of Shor's Algorithm for integer factorization.
    Returns a tuple of factors (p, q) or None if factorization fails.
    """
    if N % 2 == 0:
        return 2, N // 2
    
    a = random.randint(2, N - 1)
    g = math.gcd(a, N)
    
    if g != 1:
        return g, N // g
        
    r = quantum_order_finding(a, N)
    
    if r is None or r % 2 != 0:
        return None
        
    x = pow(a, r // 2, N)
    if (x + 1) % N == 0:
        return None
        
    p = math.gcd(x + 1, N)
    q = math.gcd(x - 1, N)
    
    return p, q

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 SAP.py <number_to_factor>")
        sys.exit(1)
        
    number_to_factor = int(sys.argv[1])
    factors = shors_algorithm(number_to_factor)
    print(f"Factors: {factors}")
