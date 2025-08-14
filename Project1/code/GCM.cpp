#include <chrono>
#include <random>
#include <vector>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <cstdint>
#include <immintrin.h>

using namespace std;

// 混淆盒(S盒)
static const uint8_t ConfusionBox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// T-table优化：预计算S盒和线性变换的组合结果
static uint32_t TTable[256];

static const uint8_t MasterKey[16] = {
    0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
};

static const uint32_t FixedKeys[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t RoundConstants[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// 初始化T表
void initializeTTable() {
    for (int i = 0; i < 256; ++i) {
        // 应用S盒变换
        uint8_t s = ConfusionBox[i];
        // 转换为32位值
        uint32_t val = static_cast<uint32_t>(s) << 24;
        // 应用扩散操作
        val = val ^ ((val << 2) | (val >> 30)) ^  // 循环左移2位
            ((val << 10) | (val >> 22)) ^   // 循环左移10位
            ((val << 18) | (val >> 14)) ^   // 循环左移18位
            ((val << 24) | (val >> 8));     // 循环左移24位
        TTable[i] = val;
    }
}

// 循环移位操作
static inline uint32_t circular_shift(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

// T-table优化的非线性和扩散组合变换
static inline uint32_t t_transform(uint32_t word) {
    return TTable[(word >> 24) & 0xFF] ^
        (TTable[(word >> 16) & 0xFF] << 8) ^
        (TTable[(word >> 8) & 0xFF] << 16) ^
        (TTable[word & 0xFF] << 24);
}

// 密钥生成
void generate_round_keys(const uint8_t key[16], uint32_t round_keys[32]) {
    uint32_t key_buffer[36];

    // 初始化密钥
    for (int idx = 0; idx < 4; idx++) {
        key_buffer[idx] = ((uint32_t)key[4 * idx] << 24) |
            ((uint32_t)key[4 * idx + 1] << 16) |
            ((uint32_t)key[4 * idx + 2] << 8) |
            key[4 * idx + 3];
        key_buffer[idx] ^= FixedKeys[idx];
    }

    // 生成轮密钥
    for (int idx = 0; idx < 32; idx++) {
        uint32_t mix = key_buffer[idx + 1] ^
            key_buffer[idx + 2] ^
            key_buffer[idx + 3] ^
            RoundConstants[idx];
        // 使用T-table优化密钥扩展
        uint32_t substituted = 0;
        substituted |= ConfusionBox[(mix >> 24) & 0xFF] << 24;
        substituted |= ConfusionBox[(mix >> 16) & 0xFF] << 16;
        substituted |= ConfusionBox[(mix >> 8) & 0xFF] << 8;
        substituted |= ConfusionBox[mix & 0xFF];

        round_keys[idx] = key_buffer[idx] ^ substituted ^
            circular_shift(substituted, 13) ^
            circular_shift(substituted, 23);
        key_buffer[idx + 4] = round_keys[idx];
    }
}

// T-table优化的加密过程
void encrypt_block(const uint8_t input[16], uint8_t output[16], const uint32_t round_keys[32]) {
    uint32_t state[36];

    // 加载数据
    for (int idx = 0; idx < 4; idx++) {
        state[idx] = ((uint32_t)input[4 * idx] << 24) |
            ((uint32_t)input[4 * idx + 1] << 16) |
            ((uint32_t)input[4 * idx + 2] << 8) |
            input[4 * idx + 3];
    }

    // 执行32轮加密，使用T-table优化
    for (int round = 0; round < 32; round++) {
        uint32_t combined = state[round + 1] ^
            state[round + 2] ^
            state[round + 3] ^
            round_keys[round];
        // 使用T-table进行变换
        uint32_t transformed = t_transform(combined);
        state[round + 4] = state[round] ^ transformed;
    }

    // 输出结果
    for (int idx = 0; idx < 4; idx++) {
        uint32_t value = state[35 - idx];
        output[4 * idx] = (value >> 24) & 0xFF;
        output[4 * idx + 1] = (value >> 16) & 0xFF;
        output[4 * idx + 2] = (value >> 8) & 0xFF;
        output[4 * idx + 3] = value & 0xFF;
    }
}

// GF(2^128)乘法，用于GCM的GHASH计算
static __m128i gf128_mul(__m128i a, __m128i b) {
    __m128i res = _mm_setzero_si128();

    // 预计算b的奇数次倍
    __m128i b1 = b;
    __m128i b3 = _mm_xor_si128(b, _mm_slli_epi64(b, 1));
    __m128i b5 = _mm_xor_si128(b3, _mm_slli_epi64(b, 2));
    __m128i b7 = _mm_xor_si128(b5, _mm_slli_epi64(b, 3));
    __m128i b9 = _mm_xor_si128(b7, _mm_slli_epi64(b, 4));
    __m128i b11 = _mm_xor_si128(b9, _mm_slli_epi64(b, 5));
    __m128i b13 = _mm_xor_si128(b11, _mm_slli_epi64(b, 6));
    __m128i b15 = _mm_xor_si128(b13, _mm_slli_epi64(b, 7));

    // 处理每个字节
    for (int i = 0; i < 16; ++i) {
        uint8_t a_byte = ((uint8_t*)&a)[i];

        if (a_byte & 0x01) res = _mm_xor_si128(res, b1);
        if (a_byte & 0x02) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 1));
        if (a_byte & 0x04) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 2));
        if (a_byte & 0x08) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 3));
        if (a_byte & 0x10) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 4));
        if (a_byte & 0x20) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 5));
        if (a_byte & 0x40) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 6));
        if (a_byte & 0x80) res = _mm_xor_si128(res, _mm_slli_epi64(b1, 7));

        // 移位准备下一次迭代
        b1 = _mm_slli_epi64(b1, 8);
        b3 = _mm_slli_epi64(b3, 8);
        b5 = _mm_slli_epi64(b5, 8);
        b7 = _mm_slli_epi64(b7, 8);
        b9 = _mm_slli_epi64(b9, 8);
        b11 = _mm_slli_epi64(b11, 8);
        b13 = _mm_slli_epi64(b13, 8);
        b15 = _mm_slli_epi64(b15, 8);
    }

    // 应用不可约多项式 x^128 + x^7 + x^2 + x + 1
    __m128i mask = _mm_set_epi64x(0x87, 0x00);
    __m128i carry = _mm_and_si128(_mm_srli_epi64(res, 63), mask);
    res = _mm_xor_si128(res, _mm_slli_epi64(carry, 1));

    return res;
}

// 计数器加1（用于GCM的CTR模式）
static void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

// GCM模式加密和认证
void gcm_encrypt_authenticate(
    const vector<uint8_t>& plain_data,
    vector<uint8_t>& cipher_data,
    uint8_t tag[16],  // 128位认证标签
    const uint32_t round_keys[32],
    const uint8_t iv[12],  // 96位初始化向量
    const vector<uint8_t>& additional_data  // 附加认证数据
) {
    size_t data_size = plain_data.size();
    cipher_data.resize(data_size);

    // 1. 生成初始计数器块 (J0)
    uint8_t counter[16];
    memcpy(counter, iv, 12);
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x01;

    // 2. 生成哈希密钥 H = SM4_encrypt(0^128)
    uint8_t zero_block[16] = { 0 };
    uint8_t hash_key[16];
    encrypt_block(zero_block, hash_key, round_keys);
    __m128i h = _mm_loadu_si128((const __m128i*)hash_key);

    // 3. 处理附加认证数据 (AAD)
    __m128i ghash = _mm_setzero_si128();
    size_t aad_blocks = additional_data.size() / 16;
    size_t remaining_aad = additional_data.size() % 16;

    for (size_t i = 0; i < aad_blocks; ++i) {
        const uint8_t* block = &additional_data[i * 16];
        __m128i a = _mm_loadu_si128((const __m128i*)block);
        ghash = _mm_xor_si128(ghash, a);
        ghash = gf128_mul(ghash, h);
    }

    // 处理剩余的AAD字节
    if (remaining_aad > 0) {
        uint8_t padded_block[16] = { 0 };
        memcpy(padded_block, &additional_data[aad_blocks * 16], remaining_aad);
        __m128i a = _mm_loadu_si128((const __m128i*)padded_block);
        ghash = _mm_xor_si128(ghash, a);
        ghash = gf128_mul(ghash, h);
    }

    // 4. 加密数据并更新GHASH
    size_t data_blocks = data_size / 16;
    size_t remaining_data = data_size % 16;
    uint8_t keystream[16];

    // 加密第一个计数器块获取初始密钥流
    encrypt_block(counter, keystream, round_keys);
    increment_counter(counter);

    for (size_t i = 0; i < data_blocks; ++i) {
        const uint8_t* plain_block = &plain_data[i * 16];
        uint8_t* cipher_block = &cipher_data[i * 16];

        // 生成密钥流
        encrypt_block(counter, keystream, round_keys);
        increment_counter(counter);

        // 加密（XOR）
        for (int j = 0; j < 16; ++j) {
            cipher_block[j] = plain_block[j] ^ keystream[j];
        }

        // 更新GHASH
        __m128i c = _mm_loadu_si128((const __m128i*)cipher_block);
        ghash = _mm_xor_si128(ghash, c);
        ghash = gf128_mul(ghash, h);
    }

    // 处理剩余数据
    if (remaining_data > 0) {
        const uint8_t* plain_block = &plain_data[data_blocks * 16];
        uint8_t* cipher_block = &cipher_data[data_blocks * 16];

        // 生成密钥流
        encrypt_block(counter, keystream, round_keys);
        increment_counter(counter);

        // 加密（XOR）
        for (int j = 0; j < remaining_data; ++j) {
            cipher_block[j] = plain_block[j] ^ keystream[j];
        }

        // 填充并更新GHASH
        uint8_t padded_block[16] = { 0 };
        memcpy(padded_block, cipher_block, remaining_data);
        __m128i c = _mm_loadu_si128((const __m128i*)padded_block);
        ghash = _mm_xor_si128(ghash, c);
        ghash = gf128_mul(ghash, h);
    }

    // 5. 处理长度块 (64位AAD长度 || 64位数据长度)
    uint64_t aad_bits = additional_data.size() * 8;
    uint64_t data_bits = data_size * 8;

    uint8_t length_block[16];
    memcpy(length_block, &aad_bits, 8);
    memcpy(length_block + 8, &data_bits, 8);

    __m128i len = _mm_loadu_si128((const __m128i*)length_block);
    ghash = _mm_xor_si128(ghash, len);
    ghash = gf128_mul(ghash, h);

    // 6. 生成认证标签
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    memset(j0 + 12, 0, 4);  // J0 = IV || 0^32

    uint8_t hash_value[16];
    encrypt_block(j0, hash_value, round_keys);

    _mm_storeu_si128((__m128i*)tag, _mm_xor_si128(_mm_loadu_si128((const __m128i*)hash_value), ghash));
}

int main() {
    // 初始化T表
    initializeTTable();

    // 生成轮密钥
    uint32_t round_keys[32];
    generate_round_keys(MasterKey, round_keys);

    // 创建96位初始化向量(IV)
    uint8_t iv[12];
    mt19937 rng(random_device{}());
    uniform_int_distribution<uint16_t> dist(0, 255);
    for (int i = 0; i < 12; i++) {
        iv[i] = static_cast<uint8_t>(dist(rng));
    }

    // 准备附加认证数据
    string additional_data_str = "WAANDA_GCM_AAD";
    vector<uint8_t> additional_data(additional_data_str.begin(), additional_data_str.end());

    // 准备明文数据
    string original_text = "WAANDA";
    const int repeat = 10000; // 重复多次以增加数据量
    string large_text;
    for (int i = 0; i < repeat; ++i) {
        large_text += original_text;
    }

    vector<uint8_t> plain_data(large_text.begin(), large_text.end());
    vector<uint8_t> cipher_data;
    uint8_t tag[16];

    // 执行GCM加密和认证并计时
    // 先进行一次热身加密
    gcm_encrypt_authenticate(plain_data, cipher_data, tag, round_keys, iv, additional_data);

    // 正式计时开始
    auto start_time = chrono::high_resolution_clock::now();

    gcm_encrypt_authenticate(plain_data, cipher_data, tag, round_keys, iv, additional_data);

    // 计时结束
    auto end_time = chrono::high_resolution_clock::now();
    double elapsed = chrono::duration<double, milli>(end_time - start_time).count();
    double data_size_mb = plain_data.size() / (1024.0 * 1024.0);
    double speed_mb_per_sec = data_size_mb / (elapsed / 1000.0);

    // 输出结果
    cout << "=== SM4 GCM Mode ===" << endl;
    cout << "IV: ";
    for (int i = 0; i < 12; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(iv[i]);
    }
    cout << "\nTag: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(tag[i]);
    }
    cout << "\nFirst 32 bytes of ciphertext: ";
    for (int i = 0; i < 32 && i < cipher_data.size(); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(cipher_data[i]);
    }
    cout << "\nData size: " << fixed << setprecision(3) << data_size_mb << " MB" << endl;
    cout << "AAD size: " << additional_data.size() << " bytes" << endl;
    cout << "Encryption & Authentication time: " << fixed << setprecision(3) << elapsed << " ms" << endl;
    cout << "Speed: " << fixed << setprecision(3) << speed_mb_per_sec << " MB/s" << endl;

    return 0;
}
