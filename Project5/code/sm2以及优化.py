import time
import random
import hashlib
from gmssl import sm3, func

# 定义SM2曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


# 点的表示
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


# 基础点加运算
def point_add(P, Q):
    if P.infinity:
        return Q
    if Q.infinity:
        return P
    if P.x == Q.x and P.y != Q.y:
        return Point(0, 0, True)

    if P != Q:
        lam = (Q.y - P.y) * pow(Q.x - P.x, p - 2, p) % p
    else:
        lam = (3 * P.x * P.x + a) * pow(2 * P.y, p - 2, p) % p

    x = (lam * lam - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p
    return Point(x, y)


# 基础点乘运算（未优化）
def point_mul_naive(P, k):
    result = Point(0, 0, True)
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


# 预计算T-Table用于优化点乘
def precompute_T_table(P, window_size=4):
    T = [Point(0, 0, True)] * (1 << (window_size - 1))
    T[0] = P
    for i in range(1, len(T)):
        T[i] = point_add(T[i - 1], P)
    return T


# 使用T-Table优化的点乘运算
def point_mul_optimized(P, k, window_size=4, T=None):
    if T is None:
        T = precompute_T_table(P, window_size)

    result = Point(0, 0, True)
    current = P
    bits = bin(k)[2:]  # 转换为二进制字符串
    n = len(bits)
    i = n - 1

    while i >= 0:
        if bits[i] == '0':
            current = point_add(current, current)
            i -= 1
        else:
            # 找到连续的1的最高位
            j = i
            while j >= 0 and bits[j] == '1' and (i - j + 1) <= window_size:
                j -= 1
            j += 1

            # 计算窗口内的值
            w = k >> j
            w &= (1 << (i - j + 1)) - 1

            # 调整当前点
            shift = i - j
            for _ in range(shift):
                current = point_add(current, current)

            # 添加预计算的值
            if w % 2 == 0:
                w += 1
                j -= 1
                current = point_add(current, current)

            result = point_add(result, T[(w - 1) // 2])

            i = j - 1

    return result


# 生成密钥对
def generate_key_pair():
    d = random.randint(1, n - 1)
    G = Point(Gx, Gy)
    P = point_mul_optimized(G, d)  # 使用优化的点乘
    return d, P


# SM2加密
def sm2_encrypt(P, M):
    # 这里简化实现，实际SM2加密更复杂
    k = random.randint(1, n - 1)
    G = Point(Gx, Gy)
    C1 = point_mul_optimized(G, k)  # 使用优化的点乘

    kP = point_mul_optimized(P, k)
    x2, y2 = kP.x, kP.y

    # 计算t = KDF(x2||y2, len(M))
    t = sm3.sm3_hash(func.bytes_to_list((x2.to_bytes(32, byteorder='big') +
                                         y2.to_bytes(32, byteorder='big')) * 2))
    t = bytes.fromhex(t)[:len(M)]

    # 计算C2 = M ^ t
    C2 = bytes([M[i] ^ t[i] for i in range(len(M))])

    # 计算C3 = SM3(x2||M||y2)
    C3 = sm3.sm3_hash(func.bytes_to_list(
        x2.to_bytes(32, byteorder='big') + M + y2.to_bytes(32, byteorder='big')))

    return (C1, C2, C3)


# SM2解密
def sm2_decrypt(d, C):
    C1, C2, C3 = C
    dC1 = point_mul_optimized(C1, d)  # 使用优化的点乘
    x2, y2 = dC1.x, dC1.y

    # 计算t = KDF(x2||y2, len(C2))
    t = sm3.sm3_hash(func.bytes_to_list((x2.to_bytes(32, byteorder='big') +
                                         y2.to_bytes(32, byteorder='big')) * 2))
    t = bytes.fromhex(t)[:len(C2)]

    # 计算M = C2 ^ t
    M = bytes([C2[i] ^ t[i] for i in range(len(C2))])

    # 验证C3
    u = sm3.sm3_hash(func.bytes_to_list(
        x2.to_bytes(32, byteorder='big') + M + y2.to_bytes(32, byteorder='big')))

    if u != C3:
        raise ValueError("解密失败：数据验证不通过")

    return M


# 性能测试
def performance_test():
    G = Point(Gx, Gy)
    k = random.randint(1, n - 1)

    # 未优化的点乘性能测试
    start = time.time()
    for _ in range(100):
        point_mul_naive(G, k)
    naive_time = time.time() - start

    # 优化的点乘性能测试
    T = precompute_T_table(G)
    start = time.time()
    for _ in range(100):
        point_mul_optimized(G, k, T=T)
    optimized_time = time.time() - start

    print(f"未优化的点乘（100次）：{naive_time:.4f}秒")
    print(f"优化的点乘（100次）：{optimized_time:.4f}秒")
    print(f"优化后速度提升：{naive_time / optimized_time:.2f}倍")

    return naive_time, optimized_time


# 主函数
def main():
    print("=== SM2算法实现与优化 ===")

    # 性能对比
    print("\n--- 性能对比测试 ---")
    performance_test()

    # 密钥生成
    print("\n--- 密钥对生成 ---")
    d, P = generate_key_pair()
    print(f"私钥 d: {hex(d)}")
    print(f"公钥 P: {P}")

    # 加密解密测试
    print("\n--- 加密解密测试 ---")
    message = "王安达".encode('utf-8')
    print(f"原始消息: {message.decode('utf-8')}")

    ciphertext = sm2_encrypt(P, message)
    print(f"加密后: C1={ciphertext[0]}, C2长度={len(ciphertext[1])}, C3={ciphertext[2]}")

    decrypted = sm2_decrypt(d, ciphertext)
    print(f"解密后: {decrypted.decode('utf-8')}")


if __name__ == "__main__":
    main()
