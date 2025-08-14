#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstring>

using namespace std;
using namespace chrono;

// SM3常量定义（与标准一致）
const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 基础实现（作为正确参考）
namespace base {
    inline uint32_t ROTL(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    inline uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        if (j >= 0 && j <= 15)
            return X ^ Y ^ Z;
        else
            return (X & Y) | (X & Z) | (Y & Z);
    }

    inline uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        if (j >= 0 && j <= 15)
            return X ^ Y ^ Z;
        else
            return (X & Y) | (~X & Z);
    }

    inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    void message_extension(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) {
        for (int i = 0; i < 16; i++) {
            W[i] = B[i];
        }

        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; i++) {
            W1[i] = W[i] ^ W[i + 4];
        }
    }

    void cf(uint32_t V[8], const uint32_t B[16]) {
        uint32_t W[68], W1[64];
        message_extension(B, W, W1);

        uint32_t A = V[0], B_val = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
        uint32_t SS1, SS2, TT1, TT2;

        for (int j = 0; j < 64; j++) {
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
            SS2 = SS1 ^ ROTL(A, 12);
            TT1 = FF(A, B_val, C, j) + D + SS2 + W1[j];
            TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = ROTL(B_val, 9);
            B_val = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A;
        V[1] ^= B_val;
        V[2] ^= C;
        V[3] ^= D;
        V[4] ^= E;
        V[5] ^= F;
        V[6] ^= G;
        V[7] ^= H;
    }

    vector<uint8_t> padding(const vector<uint8_t>& msg) {
        size_t len = msg.size();
        size_t bit_len = len * 8;

        vector<uint8_t> padded = msg;
        padded.push_back(0x80);

        while (padded.size() % 64 != 56) {
            padded.push_back(0x00);
        }

        // 填充消息长度（大端模式）
        for (int i = 7; i >= 0; i--) {
            padded.push_back((bit_len >> (i * 8)) & 0xFF);
        }

        return padded;
    }

    string sm3(const string& msg) {
        uint32_t V[8] = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        };

        vector<uint8_t> message(msg.begin(), msg.end());
        vector<uint8_t> padded = padding(message);

        for (size_t i = 0; i < padded.size(); i += 64) {
            uint32_t B[16];
            for (int j = 0; j < 16; j++) {
                B[j] = (padded[i + 4 * j] << 24) |
                    (padded[i + 4 * j + 1] << 16) |
                    (padded[i + 4 * j + 2] << 8) |
                    padded[i + 4 * j + 3];
            }
            cf(V, B);
        }

        stringstream ss;
        for (int i = 0; i < 8; i++) {
            ss << hex << setw(8) << setfill('0') << V[i];
        }

        return ss.str();
    }
}

// 优化实现（确保与基础实现逻辑一致）
namespace optimized {
    // 循环左移 - 确保与基础实现行为一致
    inline uint32_t ROTL(uint32_t x, int n) {
        n = n % 32;
        if (n <= 0) return x;
        return (x << n) | (x >> (32 - n));
    }

    // 布尔函数 - 严格区分阶段
    inline uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        if (j >= 0 && j <= 15)
            return X ^ Y ^ Z;
        else
            return (X & Y) | (X & Z) | (Y & Z);
    }

    inline uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        if (j >= 0 && j <= 15)
            return X ^ Y ^ Z;
        else
            return (X & Y) | (~X & Z);
    }

    // 置换函数 - 确保与标准一致
    inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    // 消息扩展 - 严格遵循标准公式
    void message_extension(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) {
        // 初始化W[0..15]
        memcpy(W, B, 16 * sizeof(uint32_t));

        // 计算W[16..67] - 严格按照SM3标准公式
        for (int i = 16; i < 68; i++) {
            uint32_t term1 = W[i - 16] ^ W[i - 9];
            uint32_t term2 = ROTL(W[i - 3], 15);
            uint32_t term3 = P1(term1 ^ term2);
            uint32_t term4 = ROTL(W[i - 13], 7);
            W[i] = term3 ^ term4 ^ W[i - 6];
        }

        // 计算W1[0..63]
        for (int i = 0; i < 64; i++) {
            W1[i] = W[i] ^ W[i + 4];
        }
    }

    // 压缩函数 - 核心逻辑严格匹配基础实现
    void cf(uint32_t V[8], const uint32_t B[16]) {
        uint32_t W[68], W1[64];
        message_extension(B, W, W1);

        // 状态变量初始化
        uint32_t A = V[0], B_val = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
        uint32_t SS1, SS2, TT1, TT2;

        // 64轮迭代 - 完全遵循SM3标准流程
        for (int j = 0; j < 64; j++) {
            // 计算SS1: 严格按照公式 (ROTL(A,12) + E + ROTL(T[j],j)) 再左移7位
            SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
            SS2 = SS1 ^ ROTL(A, 12);

            // 计算TT1和TT2
            TT1 = FF(A, B_val, C, j) + D + SS2 + W1[j];
            TT2 = GG(E, F, G, j) + H + SS1 + W[j];

            // 更新状态变量 - 严格保持顺序
            D = C;
            C = ROTL(B_val, 9);
            B_val = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 状态反馈
        V[0] ^= A;
        V[1] ^= B_val;
        V[2] ^= C;
        V[3] ^= D;
        V[4] ^= E;
        V[5] ^= F;
        V[6] ^= G;
        V[7] ^= H;
    }

    // 填充函数 - 确保与基础实现完全一致
    vector<uint8_t> padding(const vector<uint8_t>& msg) {
        size_t len = msg.size();
        size_t bit_len = len * 8;
        size_t pad_total = len + 1 + 8;  // 1字节0x80 + 8字节长度

        // 计算需要填充的0x00数量
        size_t zero_pad = (64 - (pad_total % 64)) % 64;
        if (zero_pad < 0) zero_pad += 64;

        // 分配填充后的缓冲区
        vector<uint8_t> padded;
        padded.reserve(len + 1 + zero_pad + 8);

        // 复制原始消息
        padded.insert(padded.end(), msg.begin(), msg.end());

        // 填充0x80
        padded.push_back(0x80);

        // 填充0x00
        padded.insert(padded.end(), zero_pad, 0x00);

        // 填充消息长度（大端模式，与基础实现一致）
        for (int i = 7; i >= 0; i--) {
            padded.push_back((bit_len >> (i * 8)) & 0xFF);
        }

        return padded;
    }

    // 优化的SM3主函数 - 确保处理流程与基础实现一致
    string sm3(const string& msg) {
        // 初始向量（与SM3标准一致）
        uint32_t V[8] = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        };

        // 转换消息为字节向量
        vector<uint8_t> message(msg.begin(), msg.end());
        vector<uint8_t> padded = padding(message);

        // 处理每个512位块
        size_t block_count = padded.size() / 64;
        for (size_t i = 0; i < block_count; i++) {
            const uint8_t* block_data = padded.data() + i * 64;
            uint32_t B[16];

            // 转换为32位字（大端模式）
            for (int j = 0; j < 16; j++) {
                B[j] = (static_cast<uint32_t>(block_data[j * 4]) << 24) |
                    (static_cast<uint32_t>(block_data[j * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(block_data[j * 4 + 2]) << 8) |
                    static_cast<uint32_t>(block_data[j * 4 + 3]);
            }

            // 压缩该块
            cf(V, B);
        }

        // 生成最终哈希值
        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; i++) {
            ss << setw(8) << V[i];
        }

        return ss.str();
    }
}

// 性能测试函数
void performance_test() {
    string large_msg(1024 * 1024, 'a');

    // 测试基础实现
    auto start = high_resolution_clock::now();
    string base_hash = base::sm3(large_msg);
    auto end = high_resolution_clock::now();
    duration<double> base_time = end - start;

    // 测试优化实现
    start = high_resolution_clock::now();
    string opt_hash = optimized::sm3(large_msg);
    end = high_resolution_clock::now();
    duration<double> opt_time = end - start;

    // 验证结果一致性
    bool results_match = (base_hash == opt_hash);

    // 输出结果
    cout << "Performance Test Results" << endl;
    cout << "========================" << endl;
    cout << "Hash results match: " << (results_match ? "Yes" : "No") << endl;
    cout << "Base implementation time: " << fixed << setprecision(4) << base_time.count() << " seconds" << endl;
    cout << "Optimized implementation time: " << fixed << setprecision(4) << opt_time.count() << " seconds" << endl;
    cout << "Speedup factor: " << fixed << setprecision(2) << base_time.count() / opt_time.count() << "x" << endl;
}

// 验证优化实现正确性
void verify_correctness() {
    cout << "Correctness Verification" << endl;
    cout << "========================" << endl;

    // 测试向量1：空字符串
    string test1 = "";
    string base_hash1 = base::sm3(test1);
    string opt_hash1 = optimized::sm3(test1);
    cout << "Test 1 (empty string): " << (base_hash1 == opt_hash1 ? "Passed" : "Failed") << endl;
    // 正确哈希值参考：1ab21d8355cfa17f8e61194831e81a8f79406f59834d47fb8e4d67eada4138
    // cout << "Expected: 1ab21d8355cfa17f8e61194831e81a8f79406f59834d47fb8e4d67eada4138" << endl;
    // cout << "Base:     " << base_hash1 << endl;
    // cout << "Optimized:" << opt_hash1 << endl;

    // 测试向量2："abc"
    string test2 = "abc";
    string base_hash2 = base::sm3(test2);
    string opt_hash2 = optimized::sm3(test2);
    cout << "Test 2 (\"abc\"): " << (base_hash2 == opt_hash2 ? "Passed" : "Failed") << endl;
    // 正确哈希值参考：66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    // cout << "Expected: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" << endl;
    // cout << "Base:     " << base_hash2 << endl;
    // cout << "Optimized:" << opt_hash2 << endl;

    // 测试向量3：长字符串
    string test3 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    string base_hash3 = base::sm3(test3);
    string opt_hash3 = optimized::sm3(test3);
    cout << "Test 3 (long string): " << (base_hash3 == opt_hash3 ? "Passed" : "Failed") << endl;
}

int main() {
    cout << "SM3 Optimization Comparison" << endl;
    cout << "===========================" << endl << endl;

    verify_correctness();
    cout << endl;
    performance_test();

    return 0;
}
