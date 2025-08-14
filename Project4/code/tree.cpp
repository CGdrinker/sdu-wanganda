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

// SM3哈希函数实现
namespace sm3 {
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
        n = n % 32;
        if (n <= 0) return x;
        return (x << n) | (x >> (32 - n));
    }

    // 布尔函数
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

    // 置换函数
    inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    // 消息扩展
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

    // 压缩函数
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

    // 填充消息
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

    // 计算SM3哈希
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

    // 计算两个哈希的拼接哈希
    string hash_concat(const string& a, const string& b) {
        return hash(a + b);
    }
}

// Merkle树实现
class MerkleTree {
private:
    vector<string> leaves;          // 叶子节点哈希
    vector<vector<string>> tree;    // 完整的Merkle树结构
    string root;                    // 根哈希
    map<string, size_t> leaf_index; // 叶子节点索引映射
    map<string, string> data_to_hash; // 数据到哈希的映射

    // 构建Merkle树
    void build_tree(const vector<string>& data) {
        // 计算所有叶子节点的哈希
        for (const auto& item : data) {
            string h = sm3::hash(item);
            leaves.push_back(h);
            leaf_index[h] = leaves.size() - 1;
            data_to_hash[item] = h;
        }

        // 如果叶子节点数为奇数，复制最后一个节点使其成为偶数
        if (leaves.size() % 2 != 0) {
            leaves.push_back(leaves.back());
        }

        // 初始化树的第一层（叶子节点层）
        tree.push_back(leaves);

        // 构建上层节点
        vector<string> current_level = leaves;
        while (current_level.size() > 1) {
            vector<string> next_level;

            // 两两合并哈希
            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    string combined = sm3::hash_concat(current_level[i], current_level[i + 1]);
                    next_level.push_back(combined);
                }
            }

            // 如果当前层节点数为奇数，复制最后一个节点
            if (next_level.size() % 2 != 0 && next_level.size() > 1) {
                next_level.push_back(next_level.back());
            }

            tree.push_back(next_level);
            current_level = next_level;
        }

        // 设置根哈希
        if (!tree.empty() && !tree.back().empty()) {
            root = tree.back()[0];
        }
    }

public:
    // 构造函数
    MerkleTree(const vector<string>& data) {
        build_tree(data);
    }

    // 获取根哈希
    string get_root() const {
        return root;
    }

    // 获取树的高度
    size_t get_height() const {
        return tree.size();
    }

    // 生成存在性证明
    vector<pair<string, bool>> generate_existence_proof(const string& data) {
        vector<pair<string, bool>> proof;

        // 检查数据是否存在
        auto it = data_to_hash.find(data);
        if (it == data_to_hash.end()) {
            return proof; // 不存在，返回空证明
        }

        string leaf_hash = it->second;
        size_t index = leaf_index[leaf_hash];
        size_t level = 0;

        // 向上层遍历，收集证明
        while (level < tree.size() - 1) {
            size_t sibling_index = (index % 2 == 0) ? index + 1 : index - 1;

            // 检查兄弟节点是否存在
            if (sibling_index < tree[level].size()) {
                // 记录兄弟节点哈希和当前节点是否为左节点
                proof.emplace_back(tree[level][sibling_index], (index % 2 == 0));
            }

            // 移动到上一层
            index = index / 2;
            level++;
        }

        return proof;
    }

    // 验证存在性证明
    bool verify_existence_proof(const string& data, const vector<pair<string, bool>>& proof) {
        string current_hash = sm3::hash(data);

        for (const auto& p : proof) {
            if (p.second) {
                // 当前节点是左节点，拼接方式：当前哈希 + 兄弟哈希
                current_hash = sm3::hash_concat(current_hash, p.first);
            }
            else {
                // 当前节点是右节点，拼接方式：兄弟哈希 + 当前哈希
                current_hash = sm3::hash_concat(p.first, current_hash);
            }
        }

        // 验证计算出的根哈希是否与树的根哈希一致
        return current_hash == root;
    }

    // 生成非存在性证明
    tuple<vector<pair<string, bool>>, vector<pair<string, bool>>, size_t, size_t>
        generate_non_existence_proof(const string& data) {
        // 定义并初始化证明变量
        vector<pair<string, bool>> left_proof;
        vector<pair<string, bool>> right_proof;
        size_t left_idx = string::npos;
        size_t right_idx = string::npos;

        // 获取排序后的叶子节点哈希
        vector<string> sorted_hashes;
        for (const auto& item : data_to_hash) {
            sorted_hashes.push_back(item.second);
        }
        sort(sorted_hashes.begin(), sorted_hashes.end());

        string target_hash = sm3::hash(data);
        auto it = lower_bound(sorted_hashes.begin(), sorted_hashes.end(), target_hash);

        // 找到左侧存在的节点
        if (it != sorted_hashes.begin()) {
            --it;
            string left_hash = *it;
            left_idx = leaf_index[left_hash];

            // 找到原始数据用于生成证明
            for (const auto& entry : data_to_hash) {
                if (entry.second == left_hash) {
                    left_proof = generate_existence_proof(entry.first);
                    break;
                }
            }
            ++it;
        }

        // 找到右侧存在的节点
        if (it != sorted_hashes.end()) {
            string right_hash = *it;
            right_idx = leaf_index[right_hash];

            // 找到原始数据用于生成证明
            for (const auto& entry : data_to_hash) {
                if (entry.second == right_hash) {
                    right_proof = generate_existence_proof(entry.first);
                    break;
                }
            }
        }

        return make_tuple(left_proof, right_proof, left_idx, right_idx);
    }

    // 验证非存在性证明
    bool verify_non_existence_proof(const string& data,
        const vector<pair<string, bool>>& left_proof,
        const vector<pair<string, bool>>& right_proof,
        size_t left_idx, size_t right_idx) {
        // 1. 验证左侧节点证明
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

        // 2. 验证右侧节点证明
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

        // 3. 验证目标数据确实在左右节点之间（按哈希值排序）
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

        return false; // 树为空，特殊情况
    }
};

// 测试函数
int main() {
    // 创建测试数据
    vector<string> data = {
        "apple", "banana", "cherry", "date",
        "elderberry", "fig", "grape"
    };

    // 构建Merkle树
    MerkleTree merkle_tree(data);

    // 输出根哈希
    cout << "Merkle Tree Root Hash: " << merkle_tree.get_root() << endl << endl;

    // 测试存在性证明
    string existing_data = "cherry";
    auto existence_proof = merkle_tree.generate_existence_proof(existing_data);
    bool exists = merkle_tree.verify_existence_proof(existing_data, existence_proof);
    cout << "验证 \"" << existing_data << "\" 存在性: "
        << (exists ? "成功 (存在)" : "失败") << endl;

    // 测试不存在的数据
    string non_existing_data = "orange";

    // 显式定义并初始化证明变量
    vector<pair<string, bool>> left_proof;
    vector<pair<string, bool>> right_proof;
    size_t left_idx = string::npos;
    size_t right_idx = string::npos;

    // 获取非存在性证明
    tie(left_proof, right_proof, left_idx, right_idx) =
        merkle_tree.generate_non_existence_proof(non_existing_data);

    bool not_exists = merkle_tree.verify_non_existence_proof(
        non_existing_data, left_proof, right_proof, left_idx, right_idx);
    cout << "验证 \"" << non_existing_data << "\" 不存在性: "
        << (not_exists ? "成功 (不存在)" : "失败") << endl;

    // 测试伪造数据
    string fake_data = "date"; // 实际存在的数据
    auto fake_proof = merkle_tree.generate_existence_proof("fake"); // 使用错误的证明
    bool fake_valid = merkle_tree.verify_existence_proof(fake_data, fake_proof);
    cout << "验证伪造数据 \"" << fake_data << "\" 存在性: "
        << (fake_valid ? "失败 (验证通过了伪造数据)" : "成功 (识别出伪造数据)") << endl;

    return 0;
}
