from gmpy2 import *
from Crypto.Util.number import *
import math
m,n,e,c=[],[],[],[]
filename=['Frame'+str(i) for i in range(21)]
for i in range(21):
    fd = open(filename[i],'r')
    m.append(fd.read())
    fd.close()
for frame in m:
    n.append((int((frame[0:256]),16)))
    e.append((int((frame[256:512]),16)))
    c.append((int((frame[512:768]),16)))
# print(N[0],e[0],c[0])
def invmod(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = invmod(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y
def CRT(items):
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N // n
        d, r, s = invmod(n, m)
        if d != 1:
            N = N // n
            continue
        result += a * s * m
    return result % N, N
#3,8,12,16,20解密
def small_e_5():
    data=[(c[3],n[3]),(c[8],n[8]),(c[12],n[12]),(c[16],n[16]),(c[20],n[20])]
    x,y = CRT(data)
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x), 5)
    return print(long_to_bytes(plaintext3_8_12_16_20[0]))
# small_e_5()
def small_e_3():
    data=[(c[7],n[7]),(c[11],n[11]),(c[15],n[15])]
    x,y = CRT(data)
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return print(long_to_bytes(plaintext7_11_15[0]))
# small_e_3()
#费马分解法解密10
def decompose(n):
    u,v,i = 0,0,0
    u0 = gmpy2.iroot(n, 2)[0] + 1
    while True:
        u = (u0 + i) * (u0 + i) - n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            break
        i = i + 1
    p = u0 + i + v
    return p
def femat():
    p = decompose(n[10])
    q = n[10] // p
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e[10], phi) 
    m = gmpy2.powmod(c[10], d, n[10])
    return print(long_to_bytes(m))
# femat()
#Pollard分解法解密2,6,19
def pollard(n):
    B = 2 ** 18
    a = 2
    for i in range(2, (B + 1) , 1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
    return d
def P_solve(n,e,c):
    p = pollard(n)
    q = n // p
    phi = (p - 1) * (q - 1)
    print(p)
    print(q)
    print(phi)
    d = gmpy2.invert(e, phi)
    m = gmpy2.powmod(c, d, n)
    return print(long_to_bytes(m))
# P_solve(n[2],e[2],c[2])
# P_solve(n[6],e[6],c[6])
# P_solve(n[19],e[19],c[19])
#先找到有公因子的模数
# for i in range (21):
#     for j in range (i+1,21):
#         if gmpy2.gcd(n[i],n[j])!=1 and n[i]!=n[j]:
#             print(i,j)
#因数碰撞攻击1,18
def factor_collision():
    p = gmpy2.gcd(n[1],n[18])
    q_1 = n[1] // p
    phi_1 = (p - 1) * (q_1 - 1)
    d = gmpy2.invert(e[1], phi_1)
    m_1 = gmpy2.powmod(c[1], d, n[1])
    print(long_to_bytes(m_1))
    q_2 = n[18] // p
    phi_2 = (p - 1) * (q_2 - 1)
    d = gmpy2.invert(e[18], phi_2)
    m_2 = gmpy2.powmod(c[18], d, n[18])
    print(long_to_bytes(m_2))
# factor_collision()
#公共模数攻击0,4
# for i in range (21):
#     for j in range (i+1,21):
#         if n[i]==n[j]:
#             print(i,j)
def commom_modulus():
    e1 = e[0]
    e2 = e[4]
    c1 = c[0]
    c2 = c[4]
    s1 = invmod(e1,e2)[1]
    s2 = invmod(e1,e2)[2]
    m = pow(c1,s1,n[0])*pow(c2,s2,n[0]) % n[0]
    print(long_to_bytes(m))
# commom_modulus()