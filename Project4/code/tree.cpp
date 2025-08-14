#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <tuple>
#include <map>
#include <cstring>

using namespace std;

// SM3��ϣ����ʵ��
namespace sm3 {
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

    // ѭ������
    inline uint32_t ROTL(uint32_t x, int n) {
        n = n % 32;
        if (n <= 0) return x;
        return (x << n) | (x >> (32 - n));
    }

    // ��������
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

    // �û�����
    inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    // ��Ϣ��չ
    void message_extension(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) {
        memcpy(W, B, 16 * sizeof(uint32_t));

        for (int i = 16; i < 68; i++) {
            uint32_t term1 = W[i - 16] ^ W[i - 9];
            uint32_t term2 = ROTL(W[i - 3], 15);
            uint32_t term3 = P1(term1 ^ term2);
            uint32_t term4 = ROTL(W[i - 13], 7);
            W[i] = term3 ^ term4 ^ W[i - 6];
        }

        for (int i = 0; i < 64; i++) {
            W1[i] = W[i] ^ W[i + 4];
        }
    }

    // ѹ������
    void cf(uint32_t V[8], const uint32_t B[16]) {
        uint32_t W[68], W1[64];
        message_extension(B, W, W1);

        uint32_t A = V[0], B_val = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
        uint32_t SS1, SS2, TT1, TT2;

        for (int j = 0; j < 64; j++) {
            SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
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

    // �����Ϣ
    vector<uint8_t> padding(const vector<uint8_t>& msg) {
        size_t len = msg.size();
        size_t bit_len = len * 8;
        size_t pad_total = len + 1 + 8;

        size_t zero_pad = (64 - (pad_total % 64)) % 64;
        if (zero_pad < 0) zero_pad += 64;

        vector<uint8_t> padded;
        padded.reserve(len + 1 + zero_pad + 8);
        padded.insert(padded.end(), msg.begin(), msg.end());
        padded.push_back(0x80);
        padded.insert(padded.end(), zero_pad, 0x00);

        for (int i = 7; i >= 0; i--) {
            padded.push_back((bit_len >> (i * 8)) & 0xFF);
        }

        return padded;
    }

    // ����SM3��ϣ
    string hash(const string& msg) {
        uint32_t V[8] = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        };

        vector<uint8_t> message(msg.begin(), msg.end());
        vector<uint8_t> padded = padding(message);

        size_t block_count = padded.size() / 64;
        for (size_t i = 0; i < block_count; i++) {
            const uint8_t* block_data = padded.data() + i * 64;
            uint32_t B[16];

            for (int j = 0; j < 16; j++) {
                B[j] = (static_cast<uint32_t>(block_data[j * 4]) << 24) |
                    (static_cast<uint32_t>(block_data[j * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(block_data[j * 4 + 2]) << 8) |
                    static_cast<uint32_t>(block_data[j * 4 + 3]);
            }

            cf(V, B);
        }

        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; i++) {
            ss << setw(8) << V[i];
        }

        return ss.str();
    }

    // ����������ϣ��ƴ�ӹ�ϣ
    string hash_concat(const string& a, const string& b) {
        return hash(a + b);
    }
}

// Merkle��ʵ��
class MerkleTree {
private:
    vector<string> leaves;          // Ҷ�ӽڵ��ϣ
    vector<vector<string>> tree;    // ������Merkle���ṹ
    string root;                    // ����ϣ
    map<string, size_t> leaf_index; // Ҷ�ӽڵ�����ӳ��
    map<string, string> data_to_hash; // ���ݵ���ϣ��ӳ��

    // ����Merkle��
    void build_tree(const vector<string>& data) {
        // ��������Ҷ�ӽڵ�Ĺ�ϣ
        for (const auto& item : data) {
            string h = sm3::hash(item);
            leaves.push_back(h);
            leaf_index[h] = leaves.size() - 1;
            data_to_hash[item] = h;
        }

        // ���Ҷ�ӽڵ���Ϊ�������������һ���ڵ�ʹ���Ϊż��
        if (leaves.size() % 2 != 0) {
            leaves.push_back(leaves.back());
        }

        // ��ʼ�����ĵ�һ�㣨Ҷ�ӽڵ�㣩
        tree.push_back(leaves);

        // �����ϲ�ڵ�
        vector<string> current_level = leaves;
        while (current_level.size() > 1) {
            vector<string> next_level;

            // �����ϲ���ϣ
            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    string combined = sm3::hash_concat(current_level[i], current_level[i + 1]);
                    next_level.push_back(combined);
                }
            }

            // �����ǰ��ڵ���Ϊ�������������һ���ڵ�
            if (next_level.size() % 2 != 0 && next_level.size() > 1) {
                next_level.push_back(next_level.back());
            }

            tree.push_back(next_level);
            current_level = next_level;
        }

        // ���ø���ϣ
        if (!tree.empty() && !tree.back().empty()) {
            root = tree.back()[0];
        }
    }

public:
    // ���캯��
    MerkleTree(const vector<string>& data) {
        build_tree(data);
    }

    // ��ȡ����ϣ
    string get_root() const {
        return root;
    }

    // ��ȡ���ĸ߶�
    size_t get_height() const {
        return tree.size();
    }

    // ���ɴ�����֤��
    vector<pair<string, bool>> generate_existence_proof(const string& data) {
        vector<pair<string, bool>> proof;

        // ��������Ƿ����
        auto it = data_to_hash.find(data);
        if (it == data_to_hash.end()) {
            return proof; // �����ڣ����ؿ�֤��
        }

        string leaf_hash = it->second;
        size_t index = leaf_index[leaf_hash];
        size_t level = 0;

        // ���ϲ�������ռ�֤��
        while (level < tree.size() - 1) {
            size_t sibling_index = (index % 2 == 0) ? index + 1 : index - 1;

            // ����ֵܽڵ��Ƿ����
            if (sibling_index < tree[level].size()) {
                // ��¼�ֵܽڵ��ϣ�͵�ǰ�ڵ��Ƿ�Ϊ��ڵ�
                proof.emplace_back(tree[level][sibling_index], (index % 2 == 0));
            }

            // �ƶ�����һ��
            index = index / 2;
            level++;
        }

        return proof;
    }

    // ��֤������֤��
    bool verify_existence_proof(const string& data, const vector<pair<string, bool>>& proof) {
        string current_hash = sm3::hash(data);

        for (const auto& p : proof) {
            if (p.second) {
                // ��ǰ�ڵ�����ڵ㣬ƴ�ӷ�ʽ����ǰ��ϣ + �ֵܹ�ϣ
                current_hash = sm3::hash_concat(current_hash, p.first);
            }
            else {
                // ��ǰ�ڵ����ҽڵ㣬ƴ�ӷ�ʽ���ֵܹ�ϣ + ��ǰ��ϣ
                current_hash = sm3::hash_concat(p.first, current_hash);
            }
        }

        // ��֤������ĸ���ϣ�Ƿ������ĸ���ϣһ��
        return current_hash == root;
    }

    // ���ɷǴ�����֤��
    tuple<vector<pair<string, bool>>, vector<pair<string, bool>>, size_t, size_t>
        generate_non_existence_proof(const string& data) {
        // ���岢��ʼ��֤������
        vector<pair<string, bool>> left_proof;
        vector<pair<string, bool>> right_proof;
        size_t left_idx = string::npos;
        size_t right_idx = string::npos;

        // ��ȡ������Ҷ�ӽڵ��ϣ
        vector<string> sorted_hashes;
        for (const auto& item : data_to_hash) {
            sorted_hashes.push_back(item.second);
        }
        sort(sorted_hashes.begin(), sorted_hashes.end());

        string target_hash = sm3::hash(data);
        auto it = lower_bound(sorted_hashes.begin(), sorted_hashes.end(), target_hash);

        // �ҵ������ڵĽڵ�
        if (it != sorted_hashes.begin()) {
            --it;
            string left_hash = *it;
            left_idx = leaf_index[left_hash];

            // �ҵ�ԭʼ������������֤��
            for (const auto& entry : data_to_hash) {
                if (entry.second == left_hash) {
                    left_proof = generate_existence_proof(entry.first);
                    break;
                }
            }
            ++it;
        }

        // �ҵ��Ҳ���ڵĽڵ�
        if (it != sorted_hashes.end()) {
            string right_hash = *it;
            right_idx = leaf_index[right_hash];

            // �ҵ�ԭʼ������������֤��
            for (const auto& entry : data_to_hash) {
                if (entry.second == right_hash) {
                    right_proof = generate_existence_proof(entry.first);
                    break;
                }
            }
        }

        return make_tuple(left_proof, right_proof, left_idx, right_idx);
    }

    // ��֤�Ǵ�����֤��
    bool verify_non_existence_proof(const string& data,
        const vector<pair<string, bool>>& left_proof,
        const vector<pair<string, bool>>& right_proof,
        size_t left_idx, size_t right_idx) {
        // 1. ��֤���ڵ�֤��
        bool left_valid = true;
        string left_hash;
        if (left_idx != string::npos && left_idx < tree[0].size()) {
            left_hash = tree[0][left_idx];
            string computed_left = left_hash;
            for (const auto& p : left_proof) {
                if (p.second) {
                    computed_left = sm3::hash_concat(computed_left, p.first);
                }
                else {
                    computed_left = sm3::hash_concat(p.first, computed_left);
                }
            }
            left_valid = (computed_left == root);
        }

        // 2. ��֤�Ҳ�ڵ�֤��
        bool right_valid = true;
        string right_hash;
        if (right_idx != string::npos && right_idx < tree[0].size()) {
            right_hash = tree[0][right_idx];
            string computed_right = right_hash;
            for (const auto& p : right_proof) {
                if (p.second) {
                    computed_right = sm3::hash_concat(computed_right, p.first);
                }
                else {
                    computed_right = sm3::hash_concat(p.first, computed_right);
                }
            }
            right_valid = (computed_right == root);
        }

        // 3. ��֤Ŀ������ȷʵ�����ҽڵ�֮�䣨����ϣֵ����
        string target_hash = sm3::hash(data);
        if (left_idx != string::npos && right_idx != string::npos) {
            return left_valid && right_valid && (left_hash < target_hash) && (target_hash < right_hash);
        }
        else if (left_idx != string::npos) {
            return left_valid && (left_hash < target_hash);
        }
        else if (right_idx != string::npos) {
            return right_valid && (target_hash < right_hash);
        }

        return false; // ��Ϊ�գ��������
    }
};

// ���Ժ���
int main() {
    // ������������
    vector<string> data = {
        "apple", "banana", "cherry", "date",
        "elderberry", "fig", "grape"
    };

    // ����Merkle��
    MerkleTree merkle_tree(data);

    // �������ϣ
    cout << "Merkle Tree Root Hash: " << merkle_tree.get_root() << endl << endl;

    // ���Դ�����֤��
    string existing_data = "cherry";
    auto existence_proof = merkle_tree.generate_existence_proof(existing_data);
    bool exists = merkle_tree.verify_existence_proof(existing_data, existence_proof);
    cout << "��֤ \"" << existing_data << "\" ������: "
        << (exists ? "�ɹ� (����)" : "ʧ��") << endl;

    // ���Բ����ڵ�����
    string non_existing_data = "orange";

    // ��ʽ���岢��ʼ��֤������
    vector<pair<string, bool>> left_proof;
    vector<pair<string, bool>> right_proof;
    size_t left_idx = string::npos;
    size_t right_idx = string::npos;

    // ��ȡ�Ǵ�����֤��
    tie(left_proof, right_proof, left_idx, right_idx) =
        merkle_tree.generate_non_existence_proof(non_existing_data);

    bool not_exists = merkle_tree.verify_non_existence_proof(
        non_existing_data, left_proof, right_proof, left_idx, right_idx);
    cout << "��֤ \"" << non_existing_data << "\" ��������: "
        << (not_exists ? "�ɹ� (������)" : "ʧ��") << endl;

    // ����α������
    string fake_data = "date"; // ʵ�ʴ��ڵ�����
    auto fake_proof = merkle_tree.generate_existence_proof("fake"); // ʹ�ô����֤��
    bool fake_valid = merkle_tree.verify_existence_proof(fake_data, fake_proof);
    cout << "��֤α������ \"" << fake_data << "\" ������: "
        << (fake_valid ? "ʧ�� (��֤ͨ����α������)" : "�ɹ� (ʶ���α������)") << endl;

    return 0;
}
