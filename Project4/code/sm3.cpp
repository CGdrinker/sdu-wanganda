#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>

using namespace std;

// SM3常量定义
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

// 循环左移
inline uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 压缩函数中的布尔函数
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

// 压缩函数中的置换函数
inline uint32_t P0(uint32_t x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// 消息扩展
void message_extension(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) {
    // 初始化W[0..15]
    for (int i = 0; i < 16; i++) {
        W[i] = B[i];
    }

    // 计算W[16..67]
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    }

    // 计算W1[0..63]
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }
}

// 压缩函数
void cf(uint32_t V[8], const uint32_t b[16]) {
    uint32_t W[68], W1[64];
    message_extension(b, W, W1);

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
    uint32_t SS1, SS2, TT1, TT2;

    for (int j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// 填充消息
vector<uint8_t> padding(const vector<uint8_t>& msg) {
    size_t len = msg.size();
    size_t bit_len = len * 8;

    vector<uint8_t> padded = msg;

    // 填充1
    padded.push_back(0x80);

    // 填充0，直到长度 ≡ 56 mod 64
    while (padded.size() % 64 != 56) {
        padded.push_back(0x00);
    }

    // 填充原始消息长度（64位）
    for (int i = 7; i >= 0; i--) {
        padded.push_back((bit_len >> (i * 8)) & 0xFF);
    }

    return padded;
}

// SM3主函数
string sm3(const string& msg) {
    // 初始化向量
    uint32_t V[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    // 转换消息为字节向量
    vector<uint8_t> message(msg.begin(), msg.end());

    // 填充消息
    vector<uint8_t> padded = padding(message);

    // 处理每个512位分组
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

    // 转换结果为十六进制字符串
    stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << hex << setw(8) << setfill('0') << V[i];
    }

    return ss.str();
}

// 测试函数
void test_sm3() {
    // 测试向量1：空字符串
    string test1 = "";
    string hash1 = sm3(test1);
    cout << "Test 1 (empty string): " << hash1 << endl;
    cout << "Expected:          1ab21d8355cfa17f8e61194831e81a8f79cdf746b07e46ec501a9fa9d4c7a41" << endl << endl;

    // 测试向量2："abc"
    string test2 = "abc";
    string hash2 = sm3(test2);
    cout << "Test 2 (\"abc\"): " << hash2 << endl;
    cout << "Expected:       66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" << endl << endl;

    // 测试向量3："abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    string test3 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    string hash3 = sm3(test3);
    cout << "Test 3 (long string): " << hash3 << endl;
    cout << "Expected:           debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732" << endl;
}

int main() {
    cout << "SM3 Base Implementation Test" << endl;
    cout << "============================" << endl << endl;
    test_sm3();
    return 0;
}
