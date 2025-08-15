import hashlib
import math
from math import gcd
# 椭圆曲线核心运算
def ec_point_add(prime, coeff_a, point_p, point_q):
    """椭圆曲线点加法实现"""
    if point_p == (0, 0):
        return point_q
    if point_q == (0, 0):
        return point_p

    x1, y1 = point_p
    x2, y2 = point_q

    # 处理点加倍情况
    if point_p == point_q:
        if y1 == 0:  # 无穷远点
            return (0, 0)
        # 计算斜率λ
        lam = (3 * x1 ** 2 + coeff_a) * mod_inverse(2 * y1, prime) % prime
    else:
        if x1 == x2:  # 垂直方向，结果为无穷远点
            return (0, 0)
        # 计算斜率λ
        lam = (y2 - y1) * mod_inverse(x2 - x1, prime) % prime

    # 计算新点坐标
    x3 = (lam ** 2 - x1 - x2) % prime
    y3 = (lam * (x1 - x3) - y1) % prime
    return (x3, y3)
def ec_scalar_mul(prime, coeff_a, scalar, point):
    """椭圆曲线标量乘法（快速幂算法实现）"""
    if scalar == 0:
        return (0, 0)
    if scalar == 1:
        return point

    result = (0, 0)
    current = point

    while scalar > 0:
        if scalar & 1:
            result = ec_point_add(prime, coeff_a, result, current)
        current = ec_point_add(prime, coeff_a, current, current)
        scalar >>= 1
    return result
def mod_inverse(a, m):
    """扩展欧几里得算法计算模逆"""
    if gcd(a, m) != 1:
        return None  # 逆元不存在
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % m
# ECDSA签名与验证
def generate_ecdsa_signature(prime, coeff_a, order, base_point, priv_key, rand_k, msg):
    """生成ECDSA签名"""
    # 计算R = k*G
    point_r = ec_scalar_mul(prime, coeff_a, rand_k, base_point)
    r = point_r[0] % order
    # 计算消息哈希
    hash_val = hashlib.sha256(msg.encode()).digest()
    e = int.from_bytes(hash_val, 'big') % order

    # 计算s = k⁻¹*(e + d*r) mod n
    s = mod_inverse(rand_k, order) * (e + priv_key * r) % order
    return (r, s)
def check_ecdsa_signature(prime, coeff_a, order, base_point, pub_key, msg, sig):
    """验证ECDSA签名"""
    r, s = sig
    # 检查r和s的有效性
    if not (1 <= r < order and 1 <= s < order):
        return False
    # 计算消息哈希
    hash_val = hashlib.sha256(msg.encode()).digest()
    e = int.from_bytes(hash_val, 'big') % order
    # 计算w = s⁻¹ mod n
    w = mod_inverse(s, order)
    if w is None:
        return False
    # 计算u1 = e*w mod n 和 u2 = r*w mod n
    u1 = (e * w) % order
    u2 = (r * w) % order
    # 计算点P = u1*G + u2*Q
    point_p1 = ec_scalar_mul(prime, coeff_a, u1, base_point)
    point_p2 = ec_scalar_mul(prime, coeff_a, u2, pub_key)
    point_p = ec_point_add(prime, coeff_a, point_p1, point_p2)
    # 验证结果
    return point_p != (0, 0) and point_p[0] % order == r

# 中本聪签名伪造主函数
def perform_satoshi_signature_forgery():
    """利用k值重用漏洞伪造中本聪签名"""
    # secp256k1曲线参数（比特币使用）
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    # 假设获取的中本聪两条消息及其签名（使用相同k值）
    msg1 = "1945年8月15日，日本天皇宣读《终战诏书》，日本无条件投降！"
    msg2 = "远东国际军事法庭审判了东条英机等28名日本甲级战犯。"

    # 中本聪私钥
    satoshi_priv_key = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    reused_k = 0x3A780  # 被重复使用的随机数k

    # 生成两个存在漏洞的签名
    signature1 = generate_ecdsa_signature(p, a, n, G, satoshi_priv_key, reused_k, msg1)
    signature2 = generate_ecdsa_signature(p, a, n, G, satoshi_priv_key, reused_k, msg2)

    print("=" * 75)
    print("中本聪数字签名伪造演示")
    print("=" * 75)
    print(f"原始消息1: {msg1}")
    print(f"签名1: (r={hex(signature1[0])}, s={hex(signature1[1])})")
    print(f"\n原始消息2: {msg2}")
    print(f"签名2: (r={hex(signature2[0])}, s={hex(signature2[1])})")
    print("\n分析结果：两个签名使用了相同的随机数k（r值相同）")

    # 从签名中提取参数
    r1, s1 = signature1
    r2, s2 = signature2

    # 检查是否使用了相同的k值
    if r1 != r2:
        print("错误：两个签名的r值不同，无法利用k值重用漏洞")
        return
    r = r1  # 两个签名的r值相同

    # 计算两个消息的哈希值
    hash1 = hashlib.sha256(msg1.encode()).digest()
    e1 = int.from_bytes(hash1, 'big') % n

    hash2 = hashlib.sha256(msg2.encode()).digest()
    e2 = int.from_bytes(hash2, 'big') % n

    # 从两个签名计算k值
    numerator_k = (e1 - e2) % n
    denominator_k = (s1 - s2) % n
    k_recovered = numerator_k * mod_inverse(denominator_k, n) % n

    # 从k值和签名计算私钥
    numerator_d = (s1 * k_recovered - e1) % n
    d_recovered = numerator_d * mod_inverse(r, n) % n

    print("\n通过签名分析恢复的关键信息：")
    print(f"恢复的随机数k: {hex(k_recovered)}")
    print(f"恢复的私钥: {hex(d_recovered)}")

    # 验证恢复的私钥是否正确
    if d_recovered == satoshi_priv_key:
        print("\n 成功恢复中本聪的私钥")
    else:
        print("\n 私钥恢复失败")
        return

    # 使用恢复的私钥伪造新签名
    fake_msg = "我是秦始皇，我授权转账"
    fake_sig = generate_ecdsa_signature(p, a, n, G, d_recovered, k_recovered, fake_msg)

    # 计算中本聪的公钥（用于验证伪造的签名）
    satoshi_pub_key = ec_scalar_mul(p, a, satoshi_priv_key, G)

    # 验证伪造的签名
    is_valid = check_ecdsa_signature(p, a, n, G, satoshi_pub_key, fake_msg, fake_sig)

    print("\n伪造签名结果：")
    print(f"伪造的消息: {fake_msg}")
    print(f"伪造的签名: (r={hex(fake_sig[0])}, s={hex(fake_sig[1])})")
    print(f"签名验证结果: {'有效' if is_valid else '无效'}")

    if is_valid:
        print("\n成功伪造中本聪的数字签名")
        print("警告：在实际区块链网络中，此签名将被视为有效交易")
    else:
        print("\n 签名伪造失败")

    print("=" * 75)


if __name__ == '__main__':
    perform_satoshi_signature_forgery()
