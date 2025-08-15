pragma circom 2.0.0;

// 定义有限域，使用BN254曲线的 scalar field
// Fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
include "circomlib/fields.circom";
include "circomlib/gates.circom";

// S-Box组件：实现x^5运算
template SBox5() {
    signal input in;
    signal output out;

    // 计算x^5 = x * x * x * x * x
    signal t1, t2, t3;
    
    t1 <== in * in;       // x²
    t2 <== t1 * in;       // x³
    t3 <== t2 * in;       // x⁴
    out <== t3 * in;      // x⁵
}

// 轮常数
constant ROUND_CONSTANTS[64][3] = [
    [1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12],
    [13, 14, 15], [16, 17, 18], [19, 20, 21], [22, 23, 24],
    [25, 26, 27], [28, 29, 30], [31, 32, 33], [34, 35, 36],
    [37, 38, 39], [40, 41, 42], [43, 44, 45], [46, 47, 48],
    [49, 50, 51], [52, 53, 54], [55, 56, 57], [58, 59, 60],
    [61, 62, 63], [64, 65, 66], [67, 68, 69], [70, 71, 72],
    [73, 74, 75], [76, 77, 78], [79, 80, 81], [82, 83, 84],
    [85, 86, 87], [88, 89, 90], [91, 92, 93], [94, 95, 96],
    [97, 98, 99], [100, 101, 102], [103, 104, 105], [106, 107, 108],
    [109, 110, 111], [112, 113, 114], [115, 116, 117], [118, 119, 120],
    [121, 122, 123], [124, 125, 126], [127, 128, 129], [130, 131, 132],
    [133, 134, 135], [136, 137, 138], [139, 140, 141], [142, 143, 144],
    [145, 146, 147], [148, 149, 150], [151, 152, 153], [154, 155, 156],
    [157, 158, 159], [160, 161, 162], [163, 164, 165], [166, 167, 168],
    [169, 170, 171], [172, 173, 174], [175, 176, 177], [178, 179, 180],
    [181, 182, 183], [184, 185, 186], [187, 188, 189], [190, 191, 192]
];

// MDS矩阵
constant MDS_MATRIX[3][3] = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
];

// 单轮处理组件
// isFullRound: 1表示完整轮(所有元素都应用S-Box)，0表示部分轮(只有第一个元素应用S-Box)
// roundNumber: 轮数索引
template Poseidon2Round(isFullRound, roundNumber) {
    signal input state[3];
    signal output out[3];
    
    // 1. ARK (Add Round Constants) - 添加轮常数
    signal afterARK[3];
    for (var i = 0; i < 3; i++) {
        afterARK[i] <== state[i] + ROUND_CONSTANTS[roundNumber][i];
    }
    
    // 2. S-Box - 非线性变换
    signal afterSBox[3];
    component sbox0 = SBox5();
    sbox0.in <== afterARK[0];
    afterSBox[0] <== sbox0.out;
    
    if (isFullRound == 1) {
        // 完整轮：所有元素都应用S-Box
        component sbox1 = SBox5();
        sbox1.in <== afterARK[1];
        afterSBox[1] <== sbox1.out;
        
        component sbox2 = SBox5();
        sbox2.in <== afterARK[2];
        afterSBox[2] <== sbox2.out;
    } else {
        // 部分轮：只有第一个元素应用S-Box，其余保持不变
        afterSBox[1] <== afterARK[1];
        afterSBox[2] <== afterARK[2];
    }
    
    // 3. MDS - 线性扩散层
    for (var i = 0; i < 3; i++) {
        out[i] <== 0;
        for (var j = 0; j < 3; j++) {
            out[i] <== out[i] + MDS_MATRIX[i][j] * afterSBox[j];
        }
    }
}

// Poseidon2哈希主组件
template Poseidon2Hash() {
    signal input in[2];  // 两个隐私输入
    signal output out;   // 哈希结果
    
    // 初始化状态：[in1, in2, 0]
    signal state[3];
    state[0] <== in[0];
    state[1] <== in[1];
    state[2] <== 0;
    
    // 前4轮：完整轮
    for (var r = 0; r < 4; r++) {
        component round = Poseidon2Round(1, r);
        for (var i = 0; i < 3; i++) {
            round.state[i] <== state[i];
        }
        for (var i = 0; i < 3; i++) {
            state[i] <== round.out[i];
        }
    }
    
    // 中间56轮：部分轮
    for (var r = 4; r < 4 + 56; r++) {
        component round = Poseidon2Round(0, r);
        for (var i = 0; i < 3; i++) {
            round.state[i] <== state[i];
        }
        for (var i = 0; i < 3; i++) {
            state[i] <== round.out[i];
        }
    }
    
    // 最后4轮：完整轮
    for (var r = 4 + 56; r < 64; r++) {
        component round = Poseidon2Round(1, r);
        for (var i = 0; i < 3; i++) {
            round.state[i] <== state[i];
        }
        for (var i = 0; i < 3; i++) {
            state[i] <== round.out[i];
        }
    }
    
    // 输出最终状态的第一个元素作为哈希值
    out <== state[0];
}

// 主电路：将哈希结果作为公开输入
template Main() {
    // 隐私输入：两个256位字段元素
    signal private input inPrivate[2];
    
    // 公开输入：哈希结果
    signal public input hash;
    
    // 计算哈希值
    component poseidon = Poseidon2Hash();
    poseidon.in[0] <== inPrivate[0];
    poseidon.in[1] <== inPrivate[1];
    
    // 约束：公开输入必须等于计算出的哈希值
    hash === poseidon.out;
}

// 实例化主电路
component main = Main();
    