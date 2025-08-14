#include <chrono>
#include <random>
#include <vector>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <cstdint>
#include <intrin.h>  // MSVC���ڲ�����ͷ�ļ�

// ΪMSVC����GFNIָ��ļ��ݰ汾
#ifndef _mm_gf2p8affineqb_epi64_epi64
// ʹ��MSVC�������ʵ��GFNIָ��
static __forceinline __m128i _mm_gf2p8affineqb_epi64_epi64(__m128i a, __m128i b, int c) {
    __m128i result;
    __asm {
        vmovdqu xmm0, a
        vmovdqu xmm1, b
        mov ecx, c
        gf2p8affineqb xmm0, xmm1, ecx
        vmovdqu result, xmm0
    }
    return result;
}
#endif

// ΪMSVCʵ��__cpuid_count���ݺ���
#ifndef __cpuid_count
static __forceinline void __cpuid_count(unsigned int level, unsigned int count, int* eax, int* ebx, int* ecx, int* edx) {
    __asm {
        mov eax, level
        mov ecx, count
        cpuid
        mov[eax_out], eax
        mov[ebx_out], ebx
        mov[ecx_out], ecx
        mov[edx_out], edx
    }
eax_out: *eax;
ebx_out: *ebx;
ecx_out: *ecx;
edx_out: *edx;
}
#endif

using namespace std;

// ������(S��)
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

// ���CPU�Ƿ�֧��GFNI
static bool check_gfni_support() {
    int eax, ebx, ecx, edx;
    __cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    // ���EBX�Ĵ����ĵ�8λ���ж��Ƿ�֧��GFNI
    return (ebx & (1 << 8)) != 0;
}

// ѭ����λ����
static inline uint32_t circular_shift(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

// ʹ��GFNIָ�����S�б任
static inline __m128i gfni_sbox_transform(__m128i input) {
    // ����S������
    __m128i sbox = _mm_loadu_si128((const __m128i*)ConfusionBox);

    // ʹ��GFNIָ����з���任��S�в���
    // ����������0��ʾʹ�õ�λ������Ϊ�任����
    return _mm_gf2p8affineqb_epi64_epi64(input, sbox, 0);
}

// ʹ��GFNIָ�������ɢ����
static inline __m128i gfni_diffusion(__m128i x) {
    // �����������ڲ�ͬ��λ
    __m128i x2 = x;
    __m128i x10 = x;
    __m128i x18 = x;
    __m128i x24 = x;

    // ִ��ѭ����λ
    x2 = _mm_slli_epi32(x2, 2);
    x10 = _mm_slli_epi32(x10, 10);
    x18 = _mm_slli_epi32(x18, 18);
    x24 = _mm_slli_epi32(x24, 24);

    // �������Ʋ���
    __m128i temp = _mm_srli_epi32(x, 30);  // 32-2=30
    x2 = _mm_or_si128(x2, temp);

    temp = _mm_srli_epi32(x, 22);  // 32-10=22
    x10 = _mm_or_si128(x10, temp);

    temp = _mm_srli_epi32(x, 14);  // 32-18=14
    x18 = _mm_or_si128(x18, temp);

    temp = _mm_srli_epi32(x, 8);   // 32-24=8
    x24 = _mm_or_si128(x24, temp);

    // ���������λ���
    return _mm_xor_si128(_mm_xor_si128(x, x2),
        _mm_xor_si128(x10, _mm_xor_si128(x18, x24)));
}

// ʹ��GFNI�Ż�����Կ����
void generate_round_keys_gfni(const uint8_t key[16], __m128i round_keys[32]) {
    // ����Կ���ص�128λ�Ĵ���
    __m128i key_regs[36];
    key_regs[0] = _mm_loadu_si128((const __m128i*)key);

    // Ӧ�ù̶���Կ
    __m128i fixed_key = _mm_loadu_si128((const __m128i*)FixedKeys);
    key_regs[0] = _mm_xor_si128(key_regs[0], fixed_key);

    // ����ǰ4����Կ�Ĵ���
    key_regs[1] = key_regs[0];
    key_regs[2] = key_regs[0];
    key_regs[3] = key_regs[0];

    // ��������Կ
    for (int idx = 0; idx < 32; idx++) {
        // ׼���ֳ���
        __m128i round_const = _mm_set_epi32(0, 0, 0, RoundConstants[idx]);

        // ��ϲ���
        __m128i mix = _mm_xor_si128(_mm_xor_si128(key_regs[idx + 1], key_regs[idx + 2]),
            _mm_xor_si128(key_regs[idx + 3], round_const));

        // ʹ��GFNI���з����Ա任��S�У�
        __m128i substituted = gfni_sbox_transform(mix);

        // ��Կ��չ
        __m128i rot13 = _mm_shuffle_epi32(substituted, _MM_SHUFFLE(1, 0, 3, 2));
        __m128i rot23 = _mm_shuffle_epi32(substituted, _MM_SHUFFLE(2, 1, 0, 3));

        round_keys[idx] = _mm_xor_si128(_mm_xor_si128(key_regs[idx], substituted),
            _mm_xor_si128(rot13, rot23));

        key_regs[idx + 4] = round_keys[idx];
    }
}

// ʹ��GFNI�Ż��ļ��ܿ����
void encrypt_block_gfni(const uint8_t input[16], uint8_t output[16], const __m128i round_keys[32]) {
    // �������뵽128λ�Ĵ���
    __m128i state[36];
    state[0] = _mm_loadu_si128((const __m128i*)input);

    // ���Ƴ�ʼ״̬
    state[1] = state[0];
    state[2] = state[0];
    state[3] = state[0];

    // ִ��32�ּ���
    for (int round = 0; round < 32; round++) {
        // ��ϲ���
        __m128i combined = _mm_xor_si128(_mm_xor_si128(state[round + 1], state[round + 2]),
            _mm_xor_si128(state[round + 3], round_keys[round]));

        // Ӧ��S�б任��ʹ��GFNI������ɢ����
        __m128i substituted = gfni_sbox_transform(combined);
        __m128i transformed = gfni_diffusion(substituted);

        // ����״̬
        state[round + 4] = _mm_xor_si128(state[round], transformed);
    }

    // �洢���
    _mm_storeu_si128((__m128i*)output, state[35]);
}

// CBCģʽ����
void cbc_encrypt_gfni(const vector<uint8_t>& plain_data, vector<uint8_t>& cipher_data,
    const __m128i round_keys[32], const uint8_t initialization_vector[16]) {
    size_t blocks = plain_data.size() / 16;
    cipher_data.resize(plain_data.size());

    uint8_t prev_cipher[16];
    memcpy(prev_cipher, initialization_vector, 16);

    for (size_t block_idx = 0; block_idx < blocks; block_idx++) {
        uint8_t mixed_block[16];
        const uint8_t* cur_block = &plain_data[block_idx * 16];

        // ������
        __m128i cur = _mm_loadu_si128((const __m128i*)cur_block);
        __m128i prev = _mm_loadu_si128((const __m128i*)prev_cipher);
        __m128i mixed = _mm_xor_si128(cur, prev);
        _mm_storeu_si128((__m128i*)mixed_block, mixed);

        // ʹ��GFNI�Ż��ļ��ܺ���
        encrypt_block_gfni(mixed_block, &cipher_data[block_idx * 16], round_keys);

        // ����ǰһ������
        memcpy(prev_cipher, &cipher_data[block_idx * 16], 16);
    }
}

int main() {
    // ���GFNI֧��
    if (!check_gfni_support()) {
        cerr << "����: ��CPU��֧��GFNIָ�" << endl;
        cerr << "ע��: GFNI��ҪIntel Ice Lake(��10��)���Ժ��CPU֧��" << endl;
        return 1;
    }

    // ��������Կ��GFNI�汾��
    __m128i round_keys[32];
    generate_round_keys_gfni(MasterKey, round_keys);

    // ������ʼ������
    uint8_t initialization_vector[16];
    mt19937 rng(random_device{}());
    uniform_int_distribution<uint16_t> dist(0, 255);
    for (int i = 0; i < 16; i++) {
        initialization_vector[i] = static_cast<uint8_t>(dist(rng));
    }

    // ׼����������
    string original_text = "WAANDA";
    const int repeat = 10000; // �ظ����������������
    string large_text;
    for (int i = 0; i < repeat; ++i) {
        large_text += original_text;
    }

    size_t orig_length = large_text.length();
    size_t padded_length = (orig_length + 15) & ~15;
    vector<uint8_t> padded_data(padded_length);
    memcpy(padded_data.data(), large_text.data(), orig_length);

    // �������
    uint8_t padding_value = static_cast<uint8_t>(padded_length - orig_length);
    for (size_t i = orig_length; i < padded_length; i++) {
        padded_data[i] = padding_value;
    }

    // ִ�м��ܲ���ʱ
    vector<uint8_t> encrypted_data;

    // �������
    cbc_encrypt_gfni(padded_data, encrypted_data, round_keys, initialization_vector);

    // ��ʽ��ʱ
    auto start_time = chrono::high_resolution_clock::now();
    cbc_encrypt_gfni(padded_data, encrypted_data, round_keys, initialization_vector);
    auto end_time = chrono::high_resolution_clock::now();

    // ��������ָ��
    double elapsed = chrono::duration<double, milli>(end_time - start_time).count();
    double data_size_mb = padded_data.size() / (1024.0 * 1024.0);
    double speed_mb_per_sec = data_size_mb / (elapsed / 1000.0);

    // ������
    cout << "=== SM4 GFNI�Ż�ʵ�� ===" << endl;
    cout << "��ʼ������(IV): ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(initialization_vector[i]);
    }
    cout << "\n����ǰ32�ֽ�: ";
    for (int i = 0; i < 32 && i < encrypted_data.size(); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(encrypted_data[i]);
    }
    cout << dec << "\n���ݴ�С: " << fixed << setprecision(3) << data_size_mb << " MB" << endl;
    cout << "����ʱ��: " << fixed << setprecision(3) << elapsed << " ms" << endl;
    cout << "�����ٶ�: " << fixed << setprecision(3) << speed_mb_per_sec << " MB/s" << endl;

    return 0;
}
