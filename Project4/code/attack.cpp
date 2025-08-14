#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <cstring>

using namespace std;

// SM3��������
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

// SM3���ĺ���ʵ��
namespace sm3 {
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

    // ѹ������ - �����ָ���ĳ�ʼ״̬��ʼ
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

    // ������Ϣ����䲿�֣�������ԭʼ��Ϣ��
    vector<uint8_t> get_padding(size_t original_len) {
        size_t bit_len = original_len * 8;
        size_t pad_len = 64 - (original_len % 64);

        if (pad_len < 9) pad_len += 64;

        vector<uint8_t> padding(pad_len);
        padding[0] = 0x80;
        memset(padding.data() + 1, 0, pad_len - 9);

        // ��䳤��
        uint64_t len64 = bit_len;
        for (int i = 0; i < 8; i++) {
            padding[pad_len - 8 + i] = (len64 >> (56 - i * 8)) & 0xFF;
        }

        return padding;
    }

    // ��׼SM3��ϣ����
    string hash(const string& msg) {
        uint32_t V[8] = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        };

        vector<uint8_t> message(msg.begin(), msg.end());
        size_t len = message.size();
        size_t total_len = len;

        // ����������512λ��
        size_t block_count = len / 64;
        for (size_t i = 0; i < block_count; i++) {
            const uint8_t* block = message.data() + i * 64;
            uint32_t B[16];

            for (int j = 0; j < 16; j++) {
                B[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
                    (block[j * 4 + 2] << 8) | block[j * 4 + 3];
            }
            cf(V, B);
        }

        // ����ʣ�����ݺ����
        size_t remaining = len % 64;
        vector<uint8_t> last_block(64, 0);
        memcpy(last_block.data(), message.data() + block_count * 64, remaining);

        last_block[remaining] = 0x80;

        if (remaining >= 56) {
            cf(V, reinterpret_cast<uint32_t*>(last_block.data()));
            memset(last_block.data(), 0, 64);
        }

        // ��䳤��
        uint64_t bit_len = total_len * 8;
        for (int i = 0; i < 8; i++) {
            last_block[56 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
        }

        cf(V, reinterpret_cast<uint32_t*>(last_block.data()));

        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; i++) {
            ss << setw(8) << V[i];
        }

        return ss.str();
    }

    // �Ӹ������м�״̬���������ϣ�����ڳ�����չ������
    string extend_hash(const uint32_t initial_state[8], const string& extension, size_t original_len) {
        uint32_t V[8];
        memcpy(V, initial_state, 8 * sizeof(uint32_t));

        // ����ԭʼ��Ϣ�����
        vector<uint8_t> padding = get_padding(original_len);

        // ������չ��Ϣ����� + ��չ����
        vector<uint8_t> extended_msg;
        extended_msg.insert(extended_msg.end(), padding.begin(), padding.end());
        extended_msg.insert(extended_msg.end(), extension.begin(), extension.end());

        size_t len = extended_msg.size();

        // ��������512λ��
        size_t block_count = len / 64;
        for (size_t i = 0; i < block_count; i++) {
            const uint8_t* block = extended_msg.data() + i * 64;
            uint32_t B[16];

            for (int j = 0; j < 16; j++) {
                B[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
                    (block[j * 4 + 2] << 8) | block[j * 4 + 3];
            }
            cf(V, B);
        }

        // ����ʣ�����ݺ����
        size_t remaining = len % 64;
        if (remaining > 0) {
            vector<uint8_t> last_block(64, 0);
            memcpy(last_block.data(), extended_msg.data() + block_count * 64, remaining);

            // �����ܳ��ȣ�ԭʼ���� + ��䳤�� + ��չ���ȣ�
            size_t total_extended_len = original_len + padding.size() + extension.size();
            size_t total_bit_len = total_extended_len * 8;

            last_block[remaining] = 0x80;

            if (remaining >= 56) {
                cf(V, reinterpret_cast<uint32_t*>(last_block.data()));
                memset(last_block.data(), 0, 64);
            }

            // ����ܳ���
            uint64_t bit_len = total_bit_len;
            for (int i = 0; i < 8; i++) {
                last_block[56 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
            }

            cf(V, reinterpret_cast<uint32_t*>(last_block.data()));
        }

        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; i++) {
            ss << setw(8) << V[i];
        }

        return ss.str();
    }

    // ����ϣ�ַ���ת��Ϊ�м�״̬�����ڳ�����չ������
    bool hash_to_state(const string& hash_str, uint32_t state[8]) {
        if (hash_str.length() != 64) return false;

        for (int i = 0; i < 8; i++) {
            string part = hash_str.substr(i * 8, 8);
            state[i] = stoul(part, nullptr, 16);
        }
        return true;
    }
}

// ��ʾ������չ����
void demonstrate_length_extension_attack() {
    // ��������һ��������Կ
    string secret_key = "my_secret_key_123";

    // �������ǹ�����֪����Ϣ
    string public_msg = "user=alice&amount=100";

    // ʵ�ʼ������ H(key + msg)���������߲�֪��key
    string keyed_msg = secret_key + public_msg;
    string original_hash = sm3::hash(keyed_msg);
    size_t key_len = secret_key.length();
    size_t original_msg_len = keyed_msg.length();

    cout << "Length Extension Attack Demonstration" << endl;
    cout << "=====================================" << endl << endl;
    cout << "Secret key (unknown to attacker): \"" << secret_key << "\" (length: " << key_len << ")" << endl;
    cout << "Public message: \"" << public_msg << "\"" << endl;
    cout << "Keyed message (key + msg): \"" << keyed_msg << "\"" << endl;
    cout << "Original hash (H(key + msg)): " << original_hash << endl << endl;

    // �����ߵ�Ŀ�꣺�ڲ�֪����Կ������£����� H(key + msg + padding + extension)
    string extension = "&amount=10000";  // ��������Ҫ��ӵ�����

    // ��������Ҫ�²���Կ���Ȳ��ܳɹ���������蹥���߲¶�����Կ����
    cout << "Attacker's extension: \"" << extension << "\"" << endl;
    cout << "Attacker guesses key length: " << key_len << endl << endl;

    // �����߽�ԭʼ��ϣת��Ϊ�м�״̬
    uint32_t initial_state[8];
    if (!sm3::hash_to_state(original_hash, initial_state)) {
        cout << "Failed to convert hash to state" << endl;
        return;
    }

    // ������ʹ���м�״̬����չ���ݼ�����չ��ϣ
    string extended_hash_attacker = sm3::extend_hash(initial_state, extension, original_msg_len);

    // ����ʵ�ʵ���չ��ϣ��������֤�����Ƿ�ɹ���
    vector<uint8_t> padding = sm3::get_padding(original_msg_len);
    string actual_extended_msg = keyed_msg + string(padding.begin(), padding.end()) + extension;
    string actual_extended_hash = sm3::hash(actual_extended_msg);

    // ������
    cout << "Attacker's computed extended hash: " << extended_hash_attacker << endl;
    cout << "Actual extended hash:             " << actual_extended_hash << endl << endl;

    if (extended_hash_attacker == actual_extended_hash) {
        cout << "Attack successful! The extended hashes match." << endl;
        cout << "Extended message length: " << actual_extended_msg.length() << endl;
    }
    else {
        cout << "Attack failed! The extended hashes do not match." << endl;
    }
}

// ��ʾ����Կ���Ȳ²����ʱ�����
void demonstrate_wrong_key_length() {
    string secret_key = "my_secret_key_123";
    string public_msg = "user=alice&amount=100";
    string keyed_msg = secret_key + public_msg;
    string original_hash = sm3::hash(keyed_msg);
    size_t correct_key_len = secret_key.length();
    string extension = "&amount=10000";

    cout << "\n\nDemonstration with Wrong Key Length Guess" << endl;
    cout << "========================================" << endl << endl;
    cout << "Correct key length: " << correct_key_len << endl;
    cout << "Attacker's wrong guess: " << correct_key_len + 2 << endl << endl;

    // ������ʹ�ô������Կ���Ȳ²�
    uint32_t initial_state[8];
    sm3::hash_to_state(original_hash, initial_state);
    string extended_hash_attacker = sm3::extend_hash(initial_state, extension,
        (correct_key_len + 2) + public_msg.length());

    // ����ʵ�ʵ���չ��ϣ
    vector<uint8_t> padding = sm3::get_padding(keyed_msg.length());
    string actual_extended_msg = keyed_msg + string(padding.begin(), padding.end()) + extension;
    string actual_extended_hash = sm3::hash(actual_extended_msg);

    // ������
    cout << "Attacker's computed extended hash: " << extended_hash_attacker << endl;
    cout << "Actual extended hash:             " << actual_extended_hash << endl << endl;

    if (extended_hash_attacker == actual_extended_hash) {
        cout << "Unexpected success (this should not happen with wrong key length)" << endl;
    }
    else {
        cout << "As expected, attack fails with wrong key length guess" << endl;
    }
}

int main() {
    demonstrate_length_extension_attack();
    demonstrate_wrong_key_length();
    return 0;
}
