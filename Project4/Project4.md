# Project4:SM3的软件实现与优化一、实验目标

1、从SM3的基本软件实现出发，不断对SM3的软件执行效率进行改进。

2、基于sm3的实现，验证length-extension attack

3、基于sm3的实现，根据RFC6962构建Merkle树（10w叶子节点），并构建叶子的存在性证明和不存在性证明

# 二、实验原理

**1\. SM3 哈希算法原理​**

SM3 是我国自主设计的密码哈希算法，用于计算消息的哈希值，具备抗碰撞性、抗原像攻击等安全特性。其核心流程包括消息填充、消息扩展和压缩函数三大步骤。消息填充确保消息长度为 512 位的整数倍，填充规则为：先添加一个 0x80 字节，再添加若干 0x00 字节，最后添加 64 位原始消息长度。消息扩展将 512 位消息块扩展为 132 个字（68 个 W 字和 64 个 W1 字），供压缩函数使用。压缩函数通过 64 轮迭代更新 8 个状态变量，每轮迭代利用布尔函数、置换函数和常量进行运算，最终生成 256 位哈希值。​

**2\. 优化技术原理​**

本次优化主要采用多种技术提升 SM3 性能：循环展开通过减少循环控制语句开销，提高指令级并行性；寄存器优化通过合理使用寄存器减少内存访问；内存访问优化通过调整数据访问模式提升缓存利用率；宏函数和 inline 关键字减少函数调用开销，使代码更易被编译器优化。​

**3\. 长度扩展攻击原理​**

长度扩展攻击针对哈希算法的迭代特性，攻击者可利用已知哈希值和消息长度，在无需知道原始消息的情况下，计算原始消息附加新内容后的哈希值。SM3 作为迭代型哈希算法，其压缩函数状态可被攻击者复用，通过构造特定填充和扩展消息实现攻击。​

**4\. Merkle 树原理​**

Merkle 树是一种基于哈希的数据结构，用于验证大量数据的完整性和存在性。其以叶子节点存储数据哈希，非叶子节点存储子节点哈希的拼接哈希，根节点哈希代表整个数据集的完整性。存在性证明通过提供从目标叶子到根的路径哈希验证数据存在；不存在性证明通过展示目标位置左右相邻存在数据的证明，验证目标数据不存在。

# 三、实验设计思路

**1\. 基础 SM3 实现​**

以 SM3 算法标准为依据，分模块实现消息填充、消息扩展和压缩函数。首先实现基础工具函数，如循环左移、布尔函数、置换函数；然后实现消息填充逻辑，确保消息格式符合要求；接着完成消息扩展，生成压缩函数所需的扩展字；最后实现压缩函数的 64 轮迭代，输出最终哈希值。通过标准测试向量验证实现正确性。​

**2\. SM3 优化实现​**

在基础实现正确的前提下，引入优化技术。对核心循环（如消息扩展和压缩函数迭代）进行循环展开；使用寄存器变量和 inline 关键字优化函数调用；调整内存访问顺序，提升缓存命中率；用宏函数替代部分函数调用，减少开销。设计性能测试对比优化前后的执行时间和加速比。​

**3\. 长度扩展攻击演示​**

基于基础 SM3 实现，设计攻击流程：首先计算原始消息的哈希值作为初始状态；然后构造消息填充，模拟原始消息的填充过程；最后利用初始状态和扩展消息，计算扩展后消息的哈希值。通过对比实际扩展消息的哈希值与攻击计算结果，验证攻击有效性。同时演示密钥长度猜测错误时攻击失败的情况。​

**4\. Merkle 树实现​**

基于 SM3 构建支持 10 万叶子节点的 Merkle 树。设计树节点结构存储哈希值和子节点索引；采用自底向上的方式构建树，叶子节点为数据哈希，非叶子节点为子节点哈希拼接后的哈希；实现存在性证明生成与验证，通过从叶子到根的路径哈希验证数据存在；实现不存在性证明，通过目标位置左右相邻数据的存在证明，验证目标数据不存在。

# 四、实验代码

**1\. 基础 SM3 实现的关键代码**

实现 SM3 核心压缩函数，通过 64 轮迭代更新状态变量，每轮利用消息扩展后的 W 和 W1 字，结合布尔函数和置换函数完成状态转换，最终输出更新后的状态向量。

// 压缩函数

void cf(uint32_t V\[8\], const uint32_t B\[16\]) {

uint32_t W\[68\], W1\[64\];

message_extension(B, W, W1);

uint32_t A = V\[0\], B = V\[1\], C = V\[2\], D = V\[3\];

uint32_t E = V\[4\], F = V\[5\], G = V\[6\], H = V\[7\];

uint32_t SS1, SS2, TT1, TT2;

for (int j = 0; j < 64; j++) {

SS1 = ROTL((ROTL(A, 12) + E + ROTL(T\[j\], j)), 7);

SS2 = SS1 ^ ROTL(A, 12);

TT1 = FF(A, B, C, j) + D + SS2 + W1\[j\];

TT2 = GG(E, F, G, j) + H + SS1 + W\[j\];

D = C;

C = ROTL(B, 9);

B = A;

A = TT1;

H = G;

G = ROTL(F, 19);

F = E;

E = P0(TT2);

}

V\[0\] ^= A;

V\[1\] ^= B;

V\[2\] ^= C;

V\[3\] ^= D;

V\[4\] ^= E;

V\[5\] ^= F;

V\[6\] ^= G;

V\[7\] ^= H;

}

**2\. SM3 优化实现关键代码**

通过循环展开减少循环控制开销，提高指令并行性；调整内存访问顺序，使数据访问更符合缓存特性，提升访问效率。

// 优化的消息扩展（循环展开）

void message_extension(const uint32_t B\[16\], uint32_t W\[68\], uint32_t W1\[64\]) {

// 初始化W\[0..15\]

W\[0\] = B\[0\]; W\[1\] = B\[1\]; W\[2\] = B\[2\]; W\[3\] = B\[3\];

W\[4\] = B\[4\]; W\[5\] = B\[5\]; W\[6\] = B\[6\]; W\[7\] = B\[7\];

W\[8\] = B\[8\]; W\[9\] = B\[9\]; W\[10\] = B\[10\]; W\[11\] = B\[11\];

W\[12\] = B\[12\]; W\[13\] = B\[13\]; W\[14\] = B\[14\]; W\[15\] = B\[15\];

// 循环展开4次

for (int i = 16; i < 68; i += 4) {

W\[i\] = P1(W\[i-16\] ^ W\[i-9\] ^ ROTL(W\[i-3\], 15)) ^ ROTL(W\[i-13\], 7) ^ W\[i-6\];

W\[i+1\] = P1(W\[i-15\] ^ W\[i-8\] ^ ROTL(W\[i-2\], 15)) ^ ROTL(W\[i-12\], 7) ^ W\[i-5\];

W\[i+2\] = P1(W\[i-14\] ^ W\[i-7\] ^ ROTL(W\[i-1\], 15)) ^ ROTL(W\[i-11\], 7) ^ W\[i-4\];

W\[i+3\] = P1(W\[i-13\] ^ W\[i-6\] ^ ROTL(W\[i\], 15)) ^ ROTL(W\[i-10\], 7) ^ W\[i-3\];

}

// 计算W1，循环展开8次

for (int i = 0; i < 64; i += 8) {

W1\[i\] = W\[i\] ^ W\[i+4\];

W1\[i+1\] = W\[i+1\] ^ W\[i+5\];

W1\[i+2\] = W\[i+2\] ^ W\[i+6\];

W1\[i+3\] = W\[i+3\] ^ W\[i+7\];

W1\[i+4\] = W\[i+4\] ^ W\[i+8\];

W1\[i+5\] = W\[i+5\] ^ W\[i+9\];

W1\[i+6\] = W\[i+6\] ^ W\[i+10\];

W1\[i+7\] = W\[i+7\] ^ W\[i+11\];

}

}

**3\. 长度扩展攻击关键代码**

通过复用原始哈希对应的中间状态，结合原始消息填充和扩展内容，计算扩展后消息的哈希值，实现长度扩展攻击。

// 从给定中间状态继续计算哈希

string extend_hash(const uint32_t initial_state\[8\], const string& extension, size_t original_len) {

uint32_t V\[8\];

memcpy(V, initial_state, 8 \* sizeof(uint32_t));

// 计算原始消息的填充

vector&lt;uint8_t&gt; padding = get_padding(original_len);

// 创建扩展消息：填充 + 扩展内容

vector&lt;uint8_t&gt; extended_msg;

extended_msg.insert(extended_msg.end(), padding.begin(), padding.end());

extended_msg.insert(extended_msg.end(), extension.begin(), extension.end());

// 处理扩展消息块

size_t len = extended_msg.size();

size_t block_count = len / 64;

for (size_t i = 0; i < block_count; i++) {

const uint8_t\* block = extended_msg.data() + i \* 64;

uint32_t B\[16\];

for (int j = 0; j < 16; j++) {

B\[j\] = (block\[j\*4\] << 24) | (block\[j\*4+1\] << 16) |

(block\[j\*4+2\] << 8) | block\[j\*4+3\];

}

cf(V, B);

}

// 处理剩余数据和填充（略）

return get_hash_string(V);

}

**4\. Merkle 树实现关键代码**

存在性证明通过收集目标叶子到根的路径中 sibling 节点的哈希生成；非存在性证明通过目标位置左右相邻叶子的存在证明，间接验证目标数据不存在。

// 生成存在性证明

vector&lt;pair<string, bool&gt;> generate_existence_proof(size_t index) {

vector&lt;pair<string, bool&gt;> proof;

if (index >= leaf_count) return proof;

size_t current_idx = index;

for (int level = 0; level < tree_height - 1; level++) {

size_t sibling_idx = (current_idx % 2 == 0) ? current_idx + 1 : current_idx - 1;

if (sibling_idx < tree\[level\].size()) {

proof.emplace_back(tree\[level\]\[sibling_idx\], (current_idx % 2 == 0));

}

current_idx = current_idx / 2;

}

return proof;

}

// 生成非存在性证明

tuple&lt;vector<pair<string, bool&gt;>, vector&lt;pair<string, bool&gt;>, size_t, size_t>

generate_non_existence_proof(size_t index) {

vector&lt;pair<string, bool&gt;> left_proof, right_proof;

size_t left_neighbor = (index > 0) ? index - 1 : -1;

size_t right_neighbor = (index < leaf_count - 1) ? index + 1 : -1;

if (left_neighbor != -1) left_proof = generate_existence_proof(left_neighbor);

if (right_neighbor != -1) right_proof = generate_existence_proof(right_neighbor);

return {left_proof, right_proof, left_neighbor, right_neighbor};

}

# 五、实验结果

详细可见各对应png文件

**1\. 基础 SM3 实现验证​**

通过标准测试向量验证正确性：

空字符串哈希：实现结果与标准一致

“abc”哈希：实现结果与预期一致

长字符串哈希验证通过，表明基础实现正确。

**2\. SM3 优化效果分析​**

对 1MB 数据进行哈希计算，性能对比：​

基础实现时间：0.1015 秒​

优化实现时间：0.0921 秒​

循环展开和寄存器优化显著减少了指令执行次数和内存访问开销，提升了运行效率。

**3\. 长度扩展攻击结果​**

正确猜测密钥长度时，攻击计算的扩展哈希与实际扩展消息哈希一致，攻击成功。​

错误猜测密钥长度时，扩展哈希不匹配，攻击失败。结果验证了长度扩展攻击的条件性和有效性，说明 SM3 在特定应用场景下需采取防护措施（如密钥哈希时使用 HMAC）。​

**4\. Merkle 树功能验证**​

存在性证明：对 10 万叶子节点中的随机节点生成证明，验证均通过，证明生成时间约 0.02ms。​

不存在性证明：对不存在的索引生成证明，验证通过，证明长度取决于树高（约 20 层）。​

树构建时间：10 万叶子节点构建时间约 1.2 秒，根哈希计算正确，表明 Merkle 树实现正确高效。

# 六、实验总结

本次实验完成了 SM3 算法的基础实现、优化、长度扩展攻击演示和 Merkle 树应用。基础实现严格遵循 SM3 标准，通过测试向量验证了正确性；优化实现采用多种技术，显著提升了性能；长度扩展攻击演示揭示了 SM3 在特定场景下的安全隐患；Merkle 树实现成功支持大规模节点的存在性和不存在性证明。​

实验过程中我也解决了多个技术问题：优化实现中的编译错误（如寄存器变量声明位置、循环展开边界检查）、Merkle 树中的变量未定义问题等。通过问题排查，我加深了对算法细节和优化技术的理解，巩固了专业知识。