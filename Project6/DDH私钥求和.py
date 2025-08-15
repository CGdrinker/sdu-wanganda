import random
import hashlib
import math

# 优化参数：减小密钥长度以提高速度
SECURITY_PARAMETER = 128  # 降低安全参数
PRIME_BITS = 1024  # 减小素数位数
HASH_FUNCTION = hashlib.sha256
def is_prime(n, k=3):
    """简化的Miller-Rabin素性测试，减少测试次数"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):  # 减少测试轮次
        a = random.randint(2, min(n - 2, 1 << 16))
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """优化的素数生成函数"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1  # 确保是奇数和指定位数
        if is_prime(p):
            return p


def mod_inverse(a, m):
    """扩展欧几里得算法计算模逆元"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m


def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)


class GroupElement:
    """群元素类，优化了表示方式"""

    def __init__(self, value, group):
        self.value = value % group.p
        self.group = group

    def __pow__(self, exponent):
        """快速指数运算"""
        if isinstance(exponent, GroupElement):
            exp_value = exponent.value
        else:
            exp_value = exponent
        result = pow(self.value, exp_value, self.group.p)
        return GroupElement(result, self.group)

    def __eq__(self, other):
        return isinstance(other, GroupElement) and self.value == other.value and self.group == other.group

    def __repr__(self):
        return f"GroupElement({hex(self.value)[:6]}..., {self.group.p})"


class PrimeOrderGroup:
    """优化的素数阶群实现"""

    def __init__(self, bits=PRIME_BITS):
        # 生成安全素数 p = 2q + 1
        self.q = generate_prime(bits // 2)
        self.p = 2 * self.q + 1
        while not is_prime(self.p):
            self.q = generate_prime(bits // 2)
            self.p = 2 * self.q + 1
        # 寻找生成元
        self.g = self.find_generator()

    def find_generator(self):
        """简化生成元搜索"""
        factors = {2, self.q}
        while True:
            g = random.randint(2, min(self.p - 2, 1000))  # 限制搜索范围
            is_generator = True
            for factor in factors:
                if pow(g, (self.p - 1) // factor, self.p) == 1:
                    is_generator = False
                    break
            if is_generator:
                return g

    def random_exponent(self):
        """生成随机指数"""
        return random.randint(1, self.q - 1)


class Paillier:
    """简化的Paillier加密系统"""

    def __init__(self, key_size=1024):  # 减小密钥大小
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        """快速生成密钥对"""
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)
        while p == q:
            q = generate_prime(self.key_size // 2)

        n = p * q
        g = n + 1
        lambda_ = (p - 1) * (q - 1)
        mu = mod_inverse(lambda_, n)

        return (n, g), (lambda_, mu)

    def encrypt(self, m):
        """加密消息"""
        n, g = self.public_key
        r = random.randint(1, n - 1)
        return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

    def decrypt(self, c):
        """解密密文"""
        n, _ = self.public_key
        lambda_, mu = self.private_key

        if c < 0 or c >= n * n:
            return None

        def L(x):
            return (x - 1) // n

        x = pow(c, lambda_, n * n)
        return (L(x) * mu) % n

    def add(self, c1, c2):
        """同态加法"""
        n, _ = self.public_key
        return (c1 * c2) % (n * n)


class Party:
    """参与方基类"""

    def __init__(self, name, group):
        self.name = name
        self.group = group
        self.private_key = group.random_exponent()
        self.data = None

    def set_data(self, data):
        self.data = data


class P1(Party):
    """参与方P1实现"""

    def __init__(self, group):
        super().__init__("P1", group)
        self.received_Z = None
        self.ahe_public_key = None

    def round1(self):
        """协议第一轮：处理数据并发送给P2"""
        if not self.data:
            raise ValueError("P1数据未初始化")

        hashed_exponentiated = []
        for v in self.data:
            # 哈希并映射到群元素
            hash_bytes = HASH_FUNCTION(str(v).encode()).digest()
            hash_int = int.from_bytes(hash_bytes, byteorder='big')
            h = GroupElement(hash_int % self.group.p, self.group)
            h_k1 = h ** self.private_key
            hashed_exponentiated.append(h_k1)

        random.shuffle(hashed_exponentiated)
        return hashed_exponentiated

    def round3(self, received_pairs):
        """协议第三轮：计算交集总和"""
        if not self.data or not self.received_Z or not self.ahe_public_key:
            raise ValueError("P1未准备就绪")

        # 处理接收的对
        processed_pairs = []
        for h_wj_k2, enc_tj in received_pairs:
            h_wj_k1k2 = h_wj_k2 ** self.private_key
            processed_pairs.append((h_wj_k1k2, enc_tj))

        # 识别交集
        z_set = {elem.value for elem in self.received_Z}
        intersection_enc_t = [enc_tj for h_wj_k1k2, enc_tj in processed_pairs
                              if h_wj_k1k2.value in z_set]

        # 计算总和
        if not intersection_enc_t:
            return 0

        sum_enc = intersection_enc_t[0]
        n, _ = self.ahe_public_key
        for enc_t in intersection_enc_t[1:]:
            sum_enc = (sum_enc * enc_t) % (n * n)

        # 刷新密文
        r = random.randint(1, n - 1)
        return (sum_enc * pow(r, n, n * n)) % (n * n)

    def set_ahe_public_key(self, public_key):
        self.ahe_public_key = public_key


class P2(Party):
    """参与方P2实现"""

    def __init__(self, group):
        super().__init__("P2", group)
        self.ahe = Paillier()  # 使用简化的Paillier

    def round2(self, received_from_p1):
        """协议第二轮：处理并返回数据"""
        if not self.data:
            raise ValueError("P2数据未初始化")

        # 计算Z集合
        z = [h_vi_k1 ** self.private_key for h_vi_k1 in received_from_p1]
        random.shuffle(z)

        # 处理自己的数据
        pairs = []
        for w, t in self.data:
            # 计算H(w_j)^k2
            hash_bytes = HASH_FUNCTION(str(w).encode()).digest()
            hash_int = int.from_bytes(hash_bytes, byteorder='big')
            h = GroupElement(hash_int % self.group.p, self.group)
            h_wj_k2 = h ** self.private_key

            # 加密t_j
            enc_tj = self.ahe.encrypt(t)
            pairs.append((h_wj_k2, enc_tj))

        random.shuffle(pairs)
        return z, pairs, self.ahe.public_key

    def decrypt_result(self, encrypted_sum):
        """解密结果"""
        return self.ahe.decrypt(encrypted_sum)


def run_protocol(p1_data, p2_data):
    """快速运行协议"""
    # 初始化群（使用较小的参数）
    group = PrimeOrderGroup()

    # 创建参与方
    p1 = P1(group)
    p2 = P2(group)

    # 设置数据
    p1.set_data(p1_data)
    p2.set_data(p2_data)

    print(f"P1数据: {p1_data[:5]}...")  # 简化输出
    print(f"P2数据: {p2_data[:5]}...")

    # 协议执行
    print("\n===== 协议执行开始 =====")

    # 第一轮
    print("执行第一轮")
    p1_to_p2 = p1.round1()

    # 第二轮
    print("执行第二轮")
    z, p2_to_p1, ahe_pub_key = p2.round2(p1_to_p2)
    p1.received_Z = z
    p1.set_ahe_public_key(ahe_pub_key)

    # 第三轮
    print("执行第三轮")
    encrypted_sum = p1.round3(p2_to_p1)

    # 解密结果
    print("解密结果")
    result = p2.decrypt_result(encrypted_sum)

    print("===== 协议执行结束 =====")

    # 验证结果
    p1_set = set(p1_data)
    actual_sum = sum(t for w, t in p2_data if w in p1_set)

    print(f"\n协议计算结果: {result}")
    print(f"实际交集总和: {actual_sum}")
    print(f"结果正确: {result == actual_sum}")

    return result


# 示例运行
if __name__ == "__main__":
    # 示例数据
    p1_data = ["user1", "user2", "user3", "user5", "user7"]
    p2_data = [
        ("user2", 100),
        ("user4", 200),
        ("user5", 150),
        ("user6", 50),
        ("user7", 300)
    ]

    # 运行协议
    run_protocol(p1_data, p2_data)