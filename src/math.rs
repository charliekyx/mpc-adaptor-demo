//! 模块封装了 MPC (多方计算) 协议中核心的数学原语，主要涉及 Shamir Secret Sharing (SSS)
//! 和拉格朗日插值 (Lagrange Interpolation) 的底层实现。
//!
//! ## 主要功能 (Key Features)
//!
//! 1. **拉格朗日系数计算 (`calculate_lagrange_coefficient`)**:
//!    - 用于在 t-of-n 门限签名方案中，将 Shamir 分片转换为加法分片 (Additive Share)。
//!    - 这是 MPC 签名阶段的关键步骤，确保各方可以在不暴露私钥的情况下协作生成签名。
//!
//! 2. **多项式分片生成 (`generate_polynomial_shares`)**:
//!    - 用于分布式密钥重构 (Resharing) 或密钥刷新 (Refresh)。
//!    - 通过构造随机多项式，将一个秘密值（如加法分片）拆分为多个子分片发送给其他参与方。
//!
//! ## 安全性 (Security)
//!
//! - 所有计算均在有限域 (Finite Field) 上进行，使用 `k256::Scalar` 类型。
//! - 涉及随机数生成的部分使用了加密安全的随机数生成器 (`OsRng`)。
//! - 本模块仅包含纯数学逻辑，不涉及网络通信或私钥存储。
//!
//! 
//! Rust 生态中有通用的秘密共享库 (如 `vsss-rs`)，为了避免引入因为对参与方索引 (Index) 的处理方式不同 (例如 0-based vs 1-based)可能引入的不适配问题
//! 这里先简单实现，后续可以探索直接用 vsss-rs


use elliptic_curve::Field;
use k256::Scalar;
use rand_core::OsRng;

/// 计算拉格朗日插值系数 (Lagrange Coefficient) $\lambda_i$
///
/// ### 原理 (Theory)
/// 在 Shamir Secret Sharing (SSS) 或 MPC 协议中，为了从 $t$ 个分片恢复秘密（或构造加法分片），
/// 我们利用拉格朗日插值公式。对于一组参与方索引 $S$ (其中 $|S| \ge t$)，
/// 秘密 $s = f(0)$ 可以表示为：
/// $$ f(0) = \sum_{i \in S} y_i \cdot \lambda_{i, S}(0) $$
/// 其中 $\lambda_{i, S}(0)$ 是拉格朗日基函数在 $x=0$ 处的求值，计算公式为：
/// $$ \lambda_{i, S} = \prod_{j \in S, j \neq i} \frac{x_j}{x_j - x_i} $$
///
/// ### 参数 (Parameters)
/// - `party_index`: 当前节点的索引 $x_i$ (通常为 1-based index)。
/// - `all_indices`: 参与重构的所有节点索引集合 $S = \{x_1, x_2, \dots, x_t\}$。
///
/// ### 参考文献 (References)
/// - Shamir's Secret Sharing
/// - Lagrange polynomial
pub fn calculate_lagrange_coefficient(party_index: u64, all_indices: &[u64]) -> Scalar {
    let my_x = Scalar::from(party_index);
    let mut lambda = Scalar::ONE;
    
    for &other_idx in all_indices {
        let other_x = Scalar::from(other_idx);
        if other_x == my_x {
            continue;
        }
        // Formula: lambda *= x_j / (x_j - x_i)
        // Note: In finite fields, division is multiplication by modular inverse.
        // num = x_j
        // den = x_j - x_i
        // We use a slightly different form in code often:
        // lambda_i = Product_{j!=i} (0 - x_j) / (x_i - x_j)
        // Which simplifies to Product_{j!=i} x_j / (x_j - x_i)
        
        let num = other_x;
        let den = (other_x - my_x).invert().unwrap();
        lambda *= num * den;
    }
    lambda
}

/// 生成 Shamir 秘密共享的分片 (Generate Shamir Shares)
///
/// ### 原理 (Theory)
/// 为了将一个秘密 $s$ (Secret) 分发给 $n$ 个参与方，使得任意 $t$ 个参与方可以恢复秘密，
/// 我们构造一个 $t-1$ 次多项式 $f(x)$：
/// $$ f(x) = s + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1} \pmod q $$
/// 其中：
/// - $s$ 是常数项 (秘密)。
/// - $a_1, \dots, a_{t-1}$ 是从有限域中随机选取的系数。
///
/// 每个参与方 $P_j$ (索引 $j \in \{1, \dots, n\}$) 获得的分片为 $y_j = f(j)$。
///
/// ### 用途 (Usage)
/// 此函数用于 MPC 中的 **Resharing** 阶段。每个节点将自己的加法分片 (Additive Share) 作为新的“秘密”，
/// 生成多项式并分发给其他节点，从而实现私钥的刷新或重新分配，而无需暴露完整私钥。
///
/// ### 参数 (Parameters)
/// - `secret`: 作为多项式常数项的秘密值 (Scalar)。
/// - `threshold`: 恢复秘密所需的最小节点数 $t$ (多项式阶数为 $t-1$)。
/// - `n`: 总参与方数量 (生成的份额总数)。
///
/// ### 返回值 (Returns)
/// 返回一个包含 $n$ 个 Scalar 的向量，第 $j$ 个元素对应 $x=j+1$ 处的函数值。
pub fn generate_polynomial_shares(
    secret: Scalar,
    threshold: u16,
    n: u16,
) -> Vec<Scalar> {
    // 1. 确定多项式阶数 (Degree)
    // Degree = t - 1
    let degree = (threshold as usize).saturating_sub(1);
    
    // 2. 生成随机系数 (Coefficients)
    // f(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1}
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret); // a_0 = secret

    for _ in 0..degree {
        coeffs.push(Scalar::random(&mut OsRng));
    }

    // 3. 计算每个点的份额 (Evaluation)
    // Evaluate f(x) for x = 1, 2, ..., n
    let mut shares = Vec::with_capacity(n as usize);
    for j in 1..=n {
        let x = Scalar::from(j as u64);
        let mut y = Scalar::ZERO;
        
        // Horner's Method or simple iteration for polynomial evaluation
        // y = a_0 + a_1*x + ...
        let mut x_pow = Scalar::ONE;
        for coeff in &coeffs {
            y += *coeff * x_pow;
            x_pow *= x;
        }
        shares.push(y);
    }

    shares
}