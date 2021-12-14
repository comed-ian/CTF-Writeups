import hashlib

# Elliptic curve form, E: Y^2 = X^3 + a X + b

def negate(p, point):
    x = point[0]
    y = point[1]
    return (x, -y % p)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    if a < 0:
        a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def map(A, B, p, point):
    y_squared = (point[0] ** 3 + A * point[0] + B) % p
    if (y_squared == (point[1] ** 2 % p)):
        return 1
    else:
        return 0

def mult(A, B, p, n, point):
    Q = point
    R = (0)
    while n > 0:
        if (n % 2 == 1):
            R = add(A, B, p, R, Q)
        Q = add(A, B, p, Q, Q)
        n //= 2
    return R

'''
Input: P in E(Fp) and an integer n > 0
1. Set Q = P and R = O.
2. Loop while n > 0.
  3. If n ≡ 1 mod 2, set R = R + Q.
  4. Set Q = 2 Q and n = ⌊n/2⌋.
  5. If n > 0, continue with loop at Step 2.
6. Return the point R, which equals nP.
'''
def add(A, B, p, point1, point2):
    if point1 == (0):
        return point2
    if point2 == (0):
        return point1
    x1 = point1[0]
    y1 = point1[1]
    x2 = point2[0]
    y2 = point2[1]

    if point1 == negate(p, point2):
        return (0)
    
    if point1 != point2:
        slope = (y2 - y1) * modinv(x2 - x1, p) % p
    else:
        slope = ((3 * x1 ** 2 + A) * modinv(2 * y1, p)) % p
    
    x3 = (slope ** 2 - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)
    
if __name__ == "__main__":
    A = 497
    B = 1768
    p = 9739 

    # Point Negation
    point = (8045,6936)
    # print(negate(p, point))

    # Point Addition
    P = (493, 5564)
    Q = (1539, 4742)
    R = (4403,5202)
    assert(add(A, B, p, (5274, 2841), (8669, 740)) == (1024, 4440))
    assert(add(A, B, p, (5274, 2841), (5274, 2841)) == (7284, 2107))
    res = add(A, B, p, P, P)
    res = add(A, B, p, res, Q)
    res = add(A, B, p, res, R)
    assert (map(A, B, p, res) == 1)
    # print(res) 

    # Scalar Multiplication
    assert(mult(A, B, p, 1337, (5323, 5438)) == (1089, 6931))
    # print(mult(A, B, p, 7863, (2339, 2213)))

    # Curves and Logs
    G = (1804,5368)
    q_a = (815, 3190) 
    n_b = 1829
    secret = mult(A, B, p, n_b, q_a)
    # print(hashlib.sha1(str(secret[0]).encode('utf-8')).hexdigest())

    # Efficient Exchange
    q_x = 4726
    n_b = 6534
    # if p ≡ 3 (mod 4), Lagrange found that the solutions are given by 
    # y = +/- (y^2)^((n + 1) / 4) % p
    q_y_squared = (q_x ** 3 + A * q_x + B) % p
    q_y = (q_y_squared ** ((p + 1) // 4)) % p
    assert(map(A, B, p, (q_x, q_y)) == 1)
    secret = mult(A, B, p, n_b, (q_x, q_y))
    # print(secret[0])

