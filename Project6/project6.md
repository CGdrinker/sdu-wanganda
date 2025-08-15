# project6：基于 DDH 的私密交集求和协议实验报告

## 一、实验目标

基于论文《On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality》中 Section 3.1 描述的协议，实现一个基于 DDH（Decisional Diffie-Hellman）的私密交集求和协议。



1.  实现两个参与方（P1 和 P2）之间的私密数据交互，其中 P1 持有仅含标识符的集合，P2 持有含标识符及其对应数值的集合。

2.  在不泄露双方非交集元素信息的前提下，使 P2 准确获取交集中元素对应数值的总和。

3.  验证协议的正确性和隐私保护能力，确保协议仅泄露交集大小和交集数值总和，不泄露其他私有信息。

## 二、实验原理

### （一）协议介绍

私密交集求和是 secure multiparty computation（MPC）的重要应用，旨在解决两个参与方在保护数据隐私的前提下，计算双方集合交集中元素关联数值总和的问题。在广告转化归因场景中，该协议可用于计算既看到广告又完成购买的用户总消费额，而无需泄露双方的完整用户数据。

本实验实现的基于 DDH 的私密交集求和协议，是论文中已部署的核心协议，其核心优势在于通信效率高、实现简单，且安全性基于成熟的 DDH 困难性假设。

### （二）协议原理

协议的核心原理基于以下密码学工具和交互流程：



1.  **密码学基础工具**

*   **素数阶群**：选取素数阶群  G  ，支持高效的指数运算，群中元素的运算满足 DDH 假设（即无法区分  (g, g^a, g^b, g^{ab})  与  (g, g^a, g^b, g^c)  的分布）。

*   **哈希函数**：使用哈希函数  H: U → G  将用户标识符映射到群元素，模拟随机预言机（Random Oracle），确保标识符的一致性匹配。

*   **加法同态加密**：采用 Paillier 加密系统，支持密文的同态加法（即  AEnc(m₁) ⊕ AEnc(m₂) = AEnc(m₁ + m₂)  ），用于在不解密的情况下累加交集中的数值。

1.  **协议交互流程**

*   **Setup 阶段**：P1 和 P2 分别选择私钥指数 k\_1, k\_2 ；P2 生成加法同态加密的公钥pk和私钥sk，并将pk发送给 P1。

*   **Round 1（P1 发起）**：P1 对其集合中每个标识符  v_i  计算  H(v_i)^{k_1}  ，打乱顺序后发送给 P2。

*   **Round 2（P2 处理）**：P1 对收到的  H(v_i)^{k_1}  计算  H(v_i)^{k_1k_2}  ，打乱后记为集合Z；同时对其集合中每个  (w_j, t_j)  计算  H(w_j)^{k_2}  和 AEnc(t_j)  ，打乱后发送给 P1。

*   **Round 3（P1 处理）**：P1 对收到的  H(w_j)^{k_2}  计算  H(w_j)^{k_1k_2}  ，通过与  Z  匹配识别交集；对交集中的  AEnc(t_j)  进行同态累加，刷新密文后发送给 P2。

*   **Output 阶段**：P2 使用私钥sk解密，得到交集中数值的总和。

## 三、实验设计思路

本实验以论文中 DDH 协议的流程为核心，设计实现方案如下：



1.  **密码学原语实现**：自定义素数生成（基于 Miller-Rabin 素性测试）、素数阶群（含生成元搜索）和 Paillier 加密系统。

2.  **参与方抽象**：封装 P1 和 P2 两个参与方类，分别实现对应轮次的计算和交互逻辑。

3.  **效率优化**：通过减小素数位数（从 2048 位降至 1024 位）、减少素性测试轮次、限制生成元搜索范围等方式，在保证基本安全性的前提下提高运行效率。

4.  **验证机制**：通过预设已知交集的测试数据，对比协议计算结果与实际交集总和，验证协议正确性。

## 四、实验代码

### （一）素数阶群实现（PrimeOrderGroup 类）

该类实现协议所需的素数阶群，核心功能包括生成安全素数和寻找生成元：



```
class PrimeOrderGroup:

&#x20;   def \_\_init\_\_(self, bits=PRIME\_BITS):

&#x20;       \# 生成安全素数 p = 2q + 1（q为素数）

&#x20;       self.q = generate\_prime(bits // 2)

&#x20;       self.p = 2 \* self.q + 1

&#x20;       while not is\_prime(self.p):

&#x20;           self.q = generate\_prime(bits // 2)

&#x20;           self.p = 2 \* self.q + 1

&#x20;       \# 寻找生成元

&#x20;       self.g = self.find\_generator()

&#x20;  &#x20;

&#x20;   def find\_generator(self):

&#x20;       factors = {2, self.q}  # p-1的素因数

&#x20;       while True:

&#x20;           g = random.randint(2, min(self.p - 2, 1000))

&#x20;           is\_generator = True

&#x20;           for factor in factors:

&#x20;               if pow(g, (self.p - 1) // factor, self.p) == 1:

&#x20;                   is\_generator = False

&#x20;                   break

&#x20;           if is\_generator:

&#x20;               return g
```

该类生成满足 p = 2q + 1  的安全素数p（确保群的阶为素数  q  ），并通过验证元素对p-1所有素因数的指数运算结果，找到群的生成元g，为 DDH 假设提供基础。

### （二）加法同态加密实现（Paillier 类）

该类实现简化版 Paillier 加密系统，支持加密、解密和同态加法：



```
class Paillier:

&#x20;   def \_\_init\_\_(self, key\_size=1024):

&#x20;       self.public\_key, self.private\_key = self.generate\_keys()

&#x20;  &#x20;

&#x20;   def generate\_keys(self):

&#x20;       p = generate\_prime(self.key\_size // 2)

&#x20;       q = generate\_prime(self.key\_size // 2)

&#x20;       while p == q:

&#x20;           q = generate\_prime(self.key\_size // 2)

&#x20;       n = p \* q

&#x20;       g = n + 1  # 生成元

&#x20;       lambda\_ = (p - 1) \* (q - 1)

&#x20;       mu = mod\_inverse(lambda\_, n)  # 模逆元

&#x20;       return (n, g), (lambda\_, mu)

&#x20;  &#x20;

&#x20;   def encrypt(self, m):

&#x20;       n, g = self.public\_key

&#x20;       r = random.randint(1, n - 1)

&#x20;       return (pow(g, m, n\*n) \* pow(r, n, n\*n)) % (n\*n)

&#x20;  &#x20;

&#x20;   def decrypt(self, c):

&#x20;       n, \_ = self.public\_key

&#x20;       lambda\_, mu = self.private\_key

&#x20;       def L(x): return (x - 1) // n

&#x20;       x = pow(c, lambda\_, n\*n)

&#x20;       return (L(x) \* mu) % n
```

Paillier 加密系统的公钥为  (n, g)  ，私钥为  (λ, μ)  ，其加法同态特性确保密文相乘等价于明文相加，是实现交集数值累加的核心工具。

### （三）参与方交互实现（P1 和 P2 类）

以 P1 的 Round 3 处理为例，展示交集识别和数值累加逻辑：



```
def round3(self, received\_pairs):

&#x20;   \# 计算H(w\_j)^(k1\*k2)并匹配交集

&#x20;   processed\_pairs = \[]

&#x20;   for h\_wj\_k2, enc\_tj in received\_pairs:

&#x20;       h\_wj\_k1k2 = h\_wj\_k2 \*\* self.private\_key  # 应用k1

&#x20;       processed\_pairs.append((h\_wj\_k1k2, enc\_tj))

&#x20;  &#x20;

&#x20;   \# 识别交集中的加密数值

&#x20;   z\_set = {elem.value for elem in self.received\_Z}

&#x20;   intersection\_enc\_t = \[enc\_tj for h\_wj\_k1k2, enc\_tj in processed\_pairs&#x20;

&#x20;                        if h\_wj\_k1k2.value in z\_set]

&#x20;  &#x20;

&#x20;   \# 同态累加并刷新密文

&#x20;   if not intersection\_enc\_t:

&#x20;       return 0

&#x20;   sum\_enc = intersection\_enc\_t\[0]

&#x20;   n, \_ = self.ahe\_public\_key

&#x20;   for enc\_t in intersection\_enc\_t\[1:]:

&#x20;       sum\_enc = (sum\_enc \* enc\_t) % (n \* n)  # 同态加法

&#x20;   r = random.randint(1, n - 1)

&#x20;   return (sum\_enc \* pow(r, n, n\*n)) % (n\*n)  # 密文刷新
```

P1 通过对比  H(w_j)^{k1k2}  与集合  Z  （即  H(v_i)^{k1k2}}  ）识别交集元素，再利用 Paillier 的同态特性累加交集中的数值，最后通过密文刷新增强隐私性。

## 五、实验结果分析

### （一）正确性验证

实验使用预设数据进行测试：



*   P1 数据：  ["user1", "user2", "user3", "user5", "user7"]  

*   P2 数据：  [("user2", 100), ("user4", 200), ("user5", 150), ("user6", 50), ("user7", 300)]  

实际交集为  ["user2", "user5", "user7"]  ，对应数值总和为  100 + 150 + 300 = 550  。协议运行结果输出为 550  ，与实际结果一致，验证了协议的正确性。

### （二）隐私保护保证分析

协议的隐私保护能力基于以下机制，与论文中的安全性分析一致：



1.  **非交集元素隐私保护**：通过 DDH 假设，非交集元素的指数运算结果（如  H(v_i)^{k1k2}  和  H(w_j)^{k1k2}  ）对对方而言是随机群元素，无法关联到原始标识符。

2.  **数据传输隐私**：所有传输的群元素和密文均经过打乱处理，避免通过顺序泄露元素关联信息。

3.  **数值隐私保护**：P2 的数值  t_j  通过加法同态加密传输，P1 仅能对交集中的密文进行累加，无法解密单个数值；P2 仅能获取总和，无法得知交集中的具体元素。

4.  **安全性证明**：协议在半诚实模型（honest-but-curious）下安全，即假设参与方遵循协议步骤但可能试图从交互数据中推断信息，模拟器可仅通过交集大小和总和模拟双方视图，证明协议未泄露额外信息。

## 六、实验总结

本次实验基于论文中基于 DDH 的私密交集求和协议，实现了一个可高效运行的私密计算系统。实验结果验证了协议的正确性：在不泄露非交集元素信息的前提下，P2 能准确获取交集中数值的总和。
