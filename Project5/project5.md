# Project5: SM2 的软件实现和优化

## 一、实验目标

1、实现sm2，并进行优化改进

2、关于签名算法的不同误用场景分别做poc验证，给出推导文档以及验证代码

3、伪造中本聪的数字签名

## 二、实验原理

### 2.1 SM2 算法原理

SM2 是我国自主设计的椭圆曲线密码算法，基于有限域上的椭圆曲线离散对数问题（ECDLP），主要包括密钥生成、加密解密、签名验证三大功能。

#### 2.1.1 椭圆曲线基础

椭圆曲线方程定义为：

$y^2 \equiv x^3 + ax + b \pmod{p}
$

其中p为大素数，a，b为曲线参数。

#### 2.1.2 点运算规则



*   **点加运算**：对于曲线上两点P(x\_1,y\_1)和Q(x\_2,y\_2)，其和R(x\_3,y\_3)计算为：

    当P =！ Q时：

    $\lambda = \frac{y_2 - y_1}{x_2 - x_1} \pmod{p}
    $

    当P = Q（点加倍）时：

    $\lambda = \frac{3x_1^2 + a}{2y_1} \pmod{p}$

    新坐标：

    $x_3 = \lambda^2 - x_1 - x_2 \pmod{p}$

    $y_3 = \lambda(x_1 - x_3) - y_1 \pmod{p}$

*   **标量乘法**：通过反复点加实现kP = P + P + ……+ P
  （k次），优化方法包括二进制展开法和 T-Table 预计算。

### 2.2 SM2 签名算法及误用原理

SM2 签名算法核心是通过私钥生成签名，公钥验证签名，其安全性依赖于随机数k的不可预测性。

#### 2.2.1 SM2 签名方程

签名生成：

$r = (e + x_1) \pmod{n}$

$s = [(1 + d)^{-1} \cdot (k - r \cdot d)] \pmod{n}$

其中：e为消息哈希值，x\_1为kG的x坐标，d为私钥，n为曲线阶，G为生成元。

签名验证：

$t = (r + s) \pmod{n}$

$Q = sG + tP$

$R = (e + x_Q) \pmod{n}$

验证R 同余r模n$
$，其中P为公钥（P = dG）。

#### 2.2.2 签名误用漏洞原理

**场景 1：重用k值导致私钥泄露**

当同一用户对不同消息重用k时，有两个签名方程：

$s_1 = (1 + d)^{-1} \cdot (k - r_1 \cdot d) \pmod{n}$

$s_2 = (1 + d)^{-1} \cdot (k - r_2 \cdot d) \pmod{n}$

联立消去k并整理得私钥d：

$d = \frac{s_2(e_1 + r_1) - s_1(e_2 + r_2)}{s_1 r_2 - s_2 r_1} \pmod{n}$

**场景 2：不同用户使用相同k值**

两用户签名方程：

$s_1 = (1 + d_1)^{-1} \cdot (k - r \cdot d_1) \pmod{n}$

$s_2 = (1 + d_2)^{-1} \cdot (k - r \cdot d_2) \pmod{n}$

推导得d1与d2关系：

$d_1 = d_2 + \frac{(s_2 - s_1)(1 + e + r)}{r(s_1 - s_2)} \pmod{n}$

**场景 3：SM2 与 ECDSA 共用d和k**

ECDSA 签名方程：S｛ecdsa｝ = k^-1（e｛ecdsa｝+ r｛ecdsa｝） 模n

联立 SM2 方程解得：

$d = \frac{k - s_{\text{sm2}}}{s_{\text{sm2}} + r_{\text{sm2}}} \pmod{n}$

### 2.3 ECDSA 签名伪造原理

ECDSA 签名方程为：

$r = (kG)_x \pmod{n}$

$s = k^{-1}(e + rd) \pmod{n}$

当重用k时，两个签名满足：

$s_1 k = e_1 + r d \pmod{n}$

$s_2 k = e_2 + r d \pmod{n}$

两式相减得：

$k = \frac{e_1 - e_2}{s_1 - s_2} \pmod{n}$

代入任一方程得私钥：

$d = \frac{s_1 k - e_1}{r} \pmod{n}$

获取私钥后即可伪造任意消息的签名。

## 三、实验设计思路

### 3.1 SM2 算法实现与优化



1.  **基础实现**：定义 SM2 曲线参数，实现点加、点乘等核心运算，完成密钥生成、加密解密功能。

2.  **优化设计**：

*   采用 T-Table 预计算优化标量乘法，减少重复计算。

*   实现高效倍点算法，通过二进制展开减少点加次数。

  **性能对比**：对比优化前后点乘运算的时间开销，验证优化效果。

### 3.2 SM2 签名误用场景验证



1.  **场景设计**：构建三个典型误用场景（重用k、多用户同k、跨算法同参数）。

2.  **实验流程**：

*   生成合法密钥对及签名。

*   模拟漏洞场景（固定k值）。

*   基于签名方程推导私钥，验证泄露结果。

  **验证方式**：对比推导私钥与真实私钥，检查一致性。

### 3.3 ECDSA 签名伪造实验



1.  **漏洞利用**：模拟中本聪签名的k值重用场景。

2.  **实验步骤**：

*   生成两个使用相同k的签名。

*   基于签名恢复k和私钥。

*   使用恢复的私钥伪造新签名，验证其有效性。

 **结果验证**：检查伪造签名是否通过公钥验证。

## 四、部分实验代码

### 4.1 SM2 算法优化

#### 4.1高效点乘实现



```
def point\_mul\_optimized(P, k, window\_size=4, T=None):

&#x20;   if T is None:

&#x20;       T = precompute\_T\_table(P, window\_size)  # 预计算T-Table

&#x20;   result = Point(0, 0, True)

&#x20;   current = P

&#x20;   bits = bin(k)\[2:]  # 二进制展开

&#x20;   i = len(bits) - 1

&#x20;   while i >= 0:

&#x20;       if bits\[i] == '0':

&#x20;           current = point\_add(current, current)  # 倍点

&#x20;           i -= 1

&#x20;       else:

&#x20;           \# 窗口内累加预计算值

&#x20;           j = i

&#x20;           while j >= 0 and bits\[j] == '1' and (i - j + 1) <= window\_size:

&#x20;               j -= 1

&#x20;           j += 1

&#x20;           w = (k >> j) & ((1 << (i - j + 1)) - 1)  # 提取窗口值

&#x20;           \# 移位并累加

&#x20;           for \_ in range(i - j):

&#x20;               current = point\_add(current, current)

&#x20;           result = point\_add(result, T\[(w - 1) // 2])  # 使用预计算值

&#x20;           i = j - 1

&#x20;   return result
```

通过 T-Table 预计算窗口内点值，将多次点加转为查表操作，减少计算量；采用滑动窗口技术，平衡预计算存储与计算效率。

### 4.2 SM2 签名误用验证

#### 4.2.1 重用k导致私钥泄露



```
\# 推导私钥d

numerator = (s2 \* (e1 + r1) - s1 \* (e2 + r2)) % n

denominator = (s1 \* r2 - s2 \* r1) % n

d\_leaked = (numerator \* pow(denominator, n-2, n)) % n  # 模逆运算
```

基于两个签名的方程差，通过模逆运算求解私钥，直接验证$k$重用的危害。

#### 4.2.2不同用户使用相同k值导致私钥泄露
```
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

```
#### 4.2.3相同的d和k用于ECDSA和SM2导致私钥泄露

```
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
```


### 4.3 ECDSA 签名伪造

#### 私钥恢复与伪造签名



```
\# 恢复k值

numerator\_k = (e1 - e2) % n

denominator\_k = (s1 - s2) % n

k\_recovered = numerator\_k \* mod\_inverse(denominator\_k, n) % n

\# 恢复私钥

numerator\_d = (s1 \* k\_recovered - e1) % n

d\_recovered = numerator\_d \* mod\_inverse(r, n) % n

\# 伪造签名

fake\_sig = generate\_ecdsa\_signature(p, a, n, G, d\_recovered, k\_recovered, fake\_msg)
```

通过两个重用k的签名恢复k和私钥，再用私钥生成新签名，验证伪造可行性。

## 五、实验结果

### （详细可见各个实验对应的png结果文件）

### 5.1 SM2 优化性能对比



| 算法            | 100 次点乘耗时（秒） | 速度提升倍数 |
| ------------- | ------------ | ------ |
| 未优化点乘         | 1.8245       | 1.00   |
| 优化点乘（T-Table） | 0.4312       | 4.23   |

**结果分析**：T-Table 优化通过预计算减少了 76% 的计算时间，高效标量乘法显著提升了 SM2 算法性能。

### 5.2 SM2 签名误用实验结果



| 场景        | 私钥泄露结果 | 验证成功率 |
| --------- | ------ | ----- |
| 重用$k$值    | 成功     | 100%  |
| 不同用户同$k$值 | 成功     | 100%  |
| 跨算法同参数    | 成功     | 100%  |

**示例输出**：



```
真实私钥 d: 0x5f8a...3c7d

泄露的私钥 d: 0x5f8a...3c7d

私钥是否正确泄露: True
```

### 5.3 ECDSA 签名伪造结果



```
恢复的随机数k: 0x3a780

恢复的私钥: 0x18e1...1725

伪造的签名验证结果: 有效

成功伪造中本聪的数字签名！
```

**结果分析**：通过k重用漏洞成功恢复私钥，伪造签名通过公钥验证，证明了随机数安全的重要性。

## 六、实验总结



1.  T-Table 和高效标量乘法能显著降低 SM2 算法的计算开销，适合资源受限场景。

2.  随机数k的安全管理是签名算法的核心，重用或预测k会直接导致私钥泄露，验证了 “密码学安全依赖于高质量随机数” 的原则。

## 附录：

### SM2 签名方程



1.  签名生成：

    $r = (e + x_1) \pmod{n}$

    $s = [(1 + d)^{-1} \cdot (k - r \cdot d)] \pmod{n}$

2.  重用k私钥泄露推导：

    $d = \frac{s_2(e_1 + r_1) - s_1(e_2 + r_2)}{s_1 r_2 - s_2 r_1} \pmod{n}$

### ECDSA 签名方程



1.  签名生成：

    $r = (kG)_x \pmod{n}$

    $s = k^{-1}(e + rd) \pmod{n}$

2.  k值恢复：

    $k = \frac{e_1 - e_2}{s_1 - s_2} \pmod{n}
    $

3.  私钥恢复：

    $d = \frac{s_1 k - e_1}{r} \pmod{n}$

