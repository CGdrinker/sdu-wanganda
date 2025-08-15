import random
import hashlib
from gmssl import sm3, func

# SM2曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class Point:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __eq__(self, other):
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self):
        if self.infinity:
            return "Point(infinity)"
        return f"Point({hex(self.x)}, {hex(self.y)})"


# 点加运算
def point_add(P, Q):
    if P.infinity:
        return Q
    if Q.infinity:
        return P
    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return Point(0, 0, True)

    if P != Q:
        lam = (Q.y - P.y) * pow((Q.x - P.x) % p, p - 2, p) % p
    else:
        lam = (3 * P.x * P.x + a) * pow((2 * P.y) % p, p - 2, p) % p

    x = (lam * lam - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p
    return Point(x, y)


# 点乘运算（优化实现）
def point_mul(P, k):
    result = Point(0, 0, True)
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


# 生成密钥对
def generate_key_pair():
    d = random.randint(1, n - 1)
    G = Point(Gx, Gy)
    P = point_mul(G, d)
    return d, P


# SM3哈希函数
def sm3_hash(data):
    return int(sm3.sm3_hash(func.bytes_to_list(data)), 16) % n


# SM2签名算法
def sm2_sign(d, M, k=None):
    G = Point(Gx, Gy)
    if k is None:
        k = random.randint(1, n - 1)

    # 计算Q = k*G
    Q = point_mul(G, k)
    x1 = Q.x

    # 计算e = H(M)
    e = sm3_hash(M)

    # 计算r = (e + x1) mod n
    r = (e + x1) % n
    if r == 0 or r == n - k % n:
        return sm2_sign(d, M)  # 重新生成

    # 计算s = ((1 + d)^-1 * (k - r*d)) mod n
    inv_1_plus_d = pow(1 + d, n - 2, n)
    s = (inv_1_plus_d * (k - r * d)) % n
    if s == 0:
        return sm2_sign(d, M)  # 重新生成

    return (r, s, k)


# SM2验证算法
def sm2_verify(P, M, signature):
    r, s = signature
    if r < 1 or r >= n or s < 1 or s >= n:
        return False

    G = Point(Gx, Gy)
    e = sm3_hash(M)

    # 计算t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False

    # 计算Q = s*G + t*P
    Q1 = point_mul(G, s)
    Q2 = point_mul(P, t)
    Q = point_add(Q1, Q2)

    if Q.infinity:
        return False

    # 计算R = (e + x_Q) mod n
    R = (e + Q.x) % n

    # 验证R == r
    return R == r


# ECDSA签名
def ecdsa_sign(d, M, k=None):
    G = Point(Gx, Gy)
    if k is None:
        k = random.randint(1, n - 1)

    Q = point_mul(G, k)
    r = Q.x % n
    if r == 0:
        return ecdsa_sign(d, M)

    e = int(hashlib.sha256(M).hexdigest(), 16) % n
    s = (pow(k, n - 2, n) * (e + r * d)) % n
    if s == 0:
        return ecdsa_sign(d, M)

    return (r, s, k)


# ECDSA验证
def ecdsa_verify(P, M, signature):
    r, s = signature
    if r < 1 or r >= n or s < 1 or s >= n:
        return False

    G = Point(Gx, Gy)
    e = int(hashlib.sha256(M).hexdigest(), 16) % n
    w = pow(s, n - 2, n)
    u1 = (e * w) % n
    u2 = (r * w) % n

    Q1 = point_mul(G, u1)
    Q2 = point_mul(P, u2)
    Q = point_add(Q1, Q2)

    if Q.infinity:
        return False

    return Q.x % n == r


# 场景1：重用k值导致私钥泄露
def scenario1_reuse_k():
    print("\n=== 场景1：重用k值导致私钥泄露 ===")

    # 生成密钥对
    d, P = generate_key_pair()
    print(f"真实私钥 d: {hex(d)}")

    # 两个不同的消息
    M1 = b"Message 1 for SM2 signature"
    M2 = b"Message 2 for SM2 signature"

    # 使用相同的k值进行签名
    k = random.randint(1, n - 1)
    r1, s1, _ = sm2_sign(d, M1, k)
    r2, s2, _ = sm2_sign(d, M2, k)

    print(f"消息1签名: (r={hex(r1)}, s={hex(s1)})")
    print(f"消息2签名: (r={hex(r2)}, s={hex(s2)})")

    # 验证签名
    verify1 = sm2_verify(P, M1, (r1, s1))
    verify2 = sm2_verify(P, M2, (r2, s2))
    print(f"签名1验证结果: {verify1}")
    print(f"签名2验证结果: {verify2}")

    if not (verify1 and verify2):
        print("签名验证失败，无法继续演示私钥泄露")
        return

    # 计算哈希值
    e1 = sm3_hash(M1)
    e2 = sm3_hash(M2)

    # 推导私钥d
    # 签名方程:
    # s1 = (k - r1*d) * inv(1 + d) mod n
    # s2 = (k - r2*d) * inv(1 + d) mod n
    # 两式相减并整理得:
    # d = (s2*(e1 + r1) - s1*(e2 + r2)) * inv(s1*r2 - s2*r1) mod n

    numerator = (s2 * (e1 + r1) - s1 * (e2 + r2)) % n
    denominator = (s1 * r2 - s2 * r1) % n

    # 确保分母不为零
    if denominator == 0:
        print("无法计算私钥，分母为零")
        return

    d_leaked = (numerator * pow(denominator, n - 2, n)) % n

    print(f"泄露的私钥 d: {hex(d_leaked)}")
    print(f"私钥是否正确泄露: {d == d_leaked}")


# 场景2：不同用户使用相同k值导致私钥泄露
def scenario2_same_k_different_users():
    print("\n=== 场景2：不同用户使用相同k值导致私钥泄露 ===")

    # 生成两个用户的密钥对
    d1, P1 = generate_key_pair()
    d2, P2 = generate_key_pair()
    print(f"用户1真实私钥 d1: {hex(d1)}")
    print(f"用户2真实私钥 d2: {hex(d2)}")

    # 相同的消息和k值
    M = b"Common message for both users"
    k = random.randint(1, n - 1)

    # 两个用户使用相同k值签名
    r1, s1, _ = sm2_sign(d1, M, k)
    r2, s2, _ = sm2_sign(d2, M, k)

    print(f"用户1签名: (r={hex(r1)}, s={hex(s1)})")
    print(f"用户2签名: (r={hex(r2)}, s={hex(s2)})")

    # 验证签名
    verify1 = sm2_verify(P1, M, (r1, s1))
    verify2 = sm2_verify(P2, M, (r2, s2))
    print(f"用户1签名验证结果: {verify1}")
    print(f"用户2签名验证结果: {verify2}")

    if not (verify1 and verify2):
        print("签名验证失败，无法继续演示私钥泄露")
        return

    # 计算哈希值
    e = sm3_hash(M)

    # 推导私钥关系
    # 对于相同k和M，r1 = r2 = r
    r = r1
    if r != r2:
        print("r值不相等，无法继续推导")
        return

    # 公式推导: d1 - d2 = (s2 - s1) * inv(s1 - s2) * (1 + (e + r)/r) mod n
    numerator = (s2 - s1) % n
    denominator = (s1 - s2) % n

    if denominator == 0:
        print("无法计算私钥，分母为零")
        return

    factor = (numerator * pow(denominator, n - 2, n)) % n
    term = ((1 + e + r) * pow(r, n - 2, n)) % n
    d1_leaked = (d2 + factor * term) % n

    print(f"泄露的用户1私钥 d1: {hex(d1_leaked)}")
    print(f"用户1私钥是否正确泄露: {d1 == d1_leaked}")


# 场景3：相同的d和k用于ECDSA和SM2导致私钥泄露
def scenario3_same_dk_ecdsa_sm2():
    print("\n=== 场景3：相同的d和k用于ECDSA和SM2导致私钥泄露 ===")

    # 生成密钥对
    d, P = generate_key_pair()
    print(f"真实私钥 d: {hex(d)}")

    # 相同的消息、d和k值用于两种算法
    M = b"Message signed with both ECDSA and SM2"
    k = random.randint(1, n - 1)

    # 签名
    r_sm2, s_sm2, _ = sm2_sign(d, M, k)
    r_ecdsa, s_ecdsa, _ = ecdsa_sign(d, M, k)

    print(f"SM2签名: (r={hex(r_sm2)}, s={hex(s_sm2)})")
    print(f"ECDSA签名: (r={hex(r_ecdsa)}, s={hex(s_ecdsa)})")

    # 验证签名
    verify_sm2 = sm2_verify(P, M, (r_sm2, s_sm2))
    verify_ecdsa = ecdsa_verify(P, M, (r_ecdsa, s_ecdsa))
    print(f"SM2签名验证结果: {verify_sm2}")
    print(f"ECDSA签名验证结果: {verify_ecdsa}")

    if not (verify_sm2 and verify_ecdsa):
        print("签名验证失败，无法继续演示私钥泄露")
        return

    # 计算哈希值
    e_sm2 = sm3_hash(M)
    e_ecdsa = int(hashlib.sha256(M).hexdigest(), 16) % n

    # 推导私钥d
    # 从ECDSA签名方程: s = (e + r*d)/k => d = (s*k - e)/(r*s) * s = (s*k - e)/r
    if r_ecdsa == 0:
        print("ECDSA r值为零，无法计算私钥")
        return

    d_from_ecdsa = ((s_ecdsa * k - e_ecdsa) * pow(r_ecdsa, n - 2, n)) % n

    # 从SM2签名方程: s = (k - r*d)/(1 + d) => d = (k - s)/(s + r)
    denominator_sm2 = (s_sm2 + r_sm2) % n
    if denominator_sm2 == 0:
        print("SM2分母为零，无法计算私钥")
        return

    d_from_sm2 = ((k - s_sm2) * pow(denominator_sm2, n - 2, n)) % n

    print(f"从ECDSA泄露的私钥 d: {hex(d_from_ecdsa)}")
    print(f"从SM2泄露的私钥 d: {hex(d_from_sm2)}")
    print(f"私钥是否正确泄露: {d == d_from_ecdsa and d == d_from_sm2}")


def main():
    print("=== SM2签名算法误用场景演示 ===")
    scenario1_reuse_k()
    scenario2_same_k_different_users()
    scenario3_same_dk_ecdsa_sm2()


if __name__ == "__main__":
    main()
