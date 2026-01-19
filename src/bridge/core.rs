//! # 数据转换的核心逻辑 (Core Bridge Logic)
//!
//! ## 核心目标 (The Goal)
//! 本模块的核心目标是实现 **Additive Secret Sharing (加法秘密共享)** 与 **Shamir Secret Sharing (Shamir 秘密共享)**
//! 之间的双向转换。这是连接不同 MPC 协议库（如 `cggmp24` 和 `synedrion`）的关键桥梁。
//!
//! ## 原理 (Principles)
//!
//! 1. **Shamir Secret Sharing (SSS)**:
//!    - **原理**: 基于多项式插值。秘密 s 是 t-1 次多项式 f(x) 的常数项 (f(0))。
//!    - **特点**: t-of-n 门限方案，具有容错性，任意 t 个参与方即可恢复秘密。
//!    - **应用**: `cggmp24` 主要使用此方案。
//!
//! 2. **Additive Secret Sharing**:
//!    - **原理**: 基于加法。秘密 s 被拆分为 n 个分片 x_i，满足 s = sum x_i pmod q。
//!    - **特点**: n-of-n 方案，所有分片必须同时存在才能恢复秘密。计算简单（线性同态）。
//!    - **应用**: `synedrion` 的某些阶段或为了简化跨协议操作时使用。
//!
//! ## 转换逻辑与挑战 (Conversion & Challenges)
//!
//! ### 1. Shamir -> Additive (Local)
//! - **方法**: 使用拉格朗日插值公式 (Lagrange Interpolation)。
//! - **公式**: w_i = x_i * lambda_{i, S}(0)，其中 S 是选定的 t 个参与方集合。
//! - **注意**: 这是一个本地计算，不需要通信。但生成的加法分片 w_i 仅对特定的集合 S 有效。
//!
//! ### 2. Additive -> Shamir (Interactive)
//! - **方法**: 完备秘密共享 (Verifiable Secret Sharing) 或重共享 (Resharing)。
//! - **流程**: 每个持有加法分片 w_i 的方，将其视为秘密，生成一个新的多项式 g_i(x) 并分发子分片。
//!   最终的新 Shamir 分片是所有收到的子分片之和。
//! - **注意**: 这是一个交互式协议，涉及 O(n^2)的网络通信。
//!
//! ## 难点
//! 1. **数学假设不一致**: 不同库对椭圆曲线标量域、参与方索引 (0-based vs 1-based) 的处理可能不同，微小的偏差会导致无法恢复私钥。
//! 2. **安全性边界**: 在转换过程中，必须确保**完整的私钥 x 从未在任何一台机器上被重构。
//!    - `Shamir -> Additive` 是安全的本地操作。
//!    - `Additive -> Shamir` 必须通过 MPC 协议（如 Resharing）进行，如果简化为“收集所有分片再重新分发”，则破坏了 MPC 的去中心化假设（变成了 Trusted Dealer 模式）。
//! 3. **状态同步**: 必须确保所有参与方在转换时使用相同的参数（如阈值 t、参与方列表 S），否则计算出的碎片将不匹配。

use super::common::{pad_hex, strip_0x, PortableKeyShare};
use anyhow::{anyhow, Context, Result};
use elliptic_curve::{Field, PrimeField};
use k256::Scalar;

/// 生成重共享多项式 (Generate Resharing Polynomial)
///
/// **功能**: 为单个加法分片生成 Shamir 子分片。
///
/// **原理**:
/// 这是 Shamir 秘密共享 (SSS) 的核心步骤。为了将一个秘密 $s$ (这里是加法分片) 分发给 $n$ 个人，
/// 我们构造一个 $t-1$ 次多项式 $f(x)$，使得 $f(0) = s$。
///
/// **流程**:
/// 1. 解析输入的 Hex 字符串为标量 (Scalar)。
/// 2. 调用 `math::generate_polynomial_shares` 生成 $n$ 个点的值 $f(1), \dots, f(n)$。
/// 3. 将结果编码回 Hex 字符串。
///
/// **生产环境通信**:
/// 此函数本身是纯计算，但在协议中，生成的这些子分片需要通过安全通道发送给其他 $n-1$ 个参与方。
pub fn generate_resharing_polynomial(
    additive_share_hex: &str,
    threshold: u16, // min_signers (degree = threshold - 1)
    n: u16,         // total parties
) -> Result<Vec<String>> {
    // 1. Parse secret (additive share)
    let padded = pad_hex(strip_0x(additive_share_hex).to_string());
    let bytes = hex::decode(&padded)?;

    let mut s_bytes = k256::FieldBytes::default();
    // Handle potential size mismatch
    if bytes.len() > 32 {
        return Err(anyhow!("Scalar bytes too long"));
    }
    let offset = 32 - bytes.len();
    s_bytes[offset..].copy_from_slice(&bytes);

    let secret = Option::<k256::Scalar>::from(k256::Scalar::from_repr(s_bytes))
        .context("Invalid scalar")?;

    // 2. Delegate math to math.rs
    let scalar_shares = crate::math::generate_polynomial_shares(secret, threshold, n);

    // 3. Convert back to Hex
    let hex_shares = scalar_shares
        .iter()
        .map(|s| hex::encode(s.to_bytes()))
        .collect();

    Ok(hex_shares)
}

/// 执行加法分片到 Shamir 分片的重共享 (Reshare Additive -> Shamir)
///
/// **功能**: 模拟 MPC 协议中的重共享过程。将一组加法分片转换为一组 Shamir 分片。
///
/// **原理**:
/// 假设全局秘密 x = sum w_i (其中 w_i 是各方的加法分片)。
/// 每个参与方 P_i 将自己的 w_i 作为秘密，通过 Shamir 共享生成子分片 w_{i...j} 发送给 P_j。
/// P_j 收到所有人的子分片后求和：x_j = sum_i w_{i...j}
/// 根据多项式的加法同态性，新的 x_j 是全局秘密 x 的一个有效 Shamir 分片
///
/// **流程**:
/// 1. **生成 (Generate)**: 每个参与方 i 为其他人生成子分片矩阵
/// 2. **分发 (Distribute)**: (模拟) 将分片发送给对应的接收方
/// 3. **聚合 (Aggregate)**: 每个接收方 j 将收到的所有子分片相加，得到新的私钥分片
///
/// **生产环境通信**:
/// **涉及**。这是一个交互式协议。在生产环境中，步骤 2 需要 O(n^2) 的网络通信，
/// 且必须通过加密通道 (如 TLS) 进行，以防子分片泄露。
pub fn additive_portable_to_shamir_portable(
    mut additive_shares: Vec<PortableKeyShare>,
    threshold: u16,
) -> Result<Vec<PortableKeyShare>> {
    let n = additive_shares.len() as u16;

    // 必须按索引排序，确保矩阵处理顺序一致 (Party 0, Party 1, ...)
    additive_shares.sort_by_key(|s| s.i);

    // 1. 每个参与方为其他所有人生成子分片 (Generate Sub-shares)
    // matrix[i][j] 表示 Party i 发送给 Party j 的分片
    let mut shares_sent: Vec<Vec<String>> = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let my_additive_share = &additive_shares[i].x_hex;
        // 生成多项式 f_i(x) 并计算 f_i(1)...f_i(n)
        let sub_shares = generate_resharing_polynomial(my_additive_share, threshold, n)?;
        shares_sent.push(sub_shares);
    }

    // 2. 每个参与方聚合收到的子分片 (Aggregate Sub-shares)
    // Party j 的新分片 = sum(matrix[i][j] for i in 0..n)
    for j in 0..n as usize {
        let mut sum_scalar = k256::Scalar::ZERO;
        for i in 0..n as usize {
            // Party j 接收来自 Party i 的分片
            let share_hex = &shares_sent[i][j];

            let padded = pad_hex(strip_0x(share_hex).to_string());
            let bytes = hex::decode(&padded)?;

            let mut s_bytes = k256::FieldBytes::default();
            let offset = 32 - bytes.len();
            s_bytes[offset..].copy_from_slice(&bytes);

            let s = Option::<k256::Scalar>::from(k256::Scalar::from_repr(s_bytes))
                .context("Invalid scalar")?;
            sum_scalar += s;
        }
        // 更新为新的 Shamir 分片
        additive_shares[j].x_hex = hex::encode(sum_scalar.to_bytes());
        additive_shares[j].t = threshold;
    }

    Ok(additive_shares)
}

/// 转换 Shamir 分片为加法分片 (Shamir -> Additive)
///
/// **功能**: 将标准的 Shamir (t-of-n) 分片转换为加法 (n-of-n) 分片
///
/// **原理**:
/// 利用拉格朗日插值公式 (Lagrange Interpolation)
/// 全局秘密 $x = f(0) = sum_{i in S} x_i * lambda_{i, S}(0)
/// 我们可以定义加法分片 $w_i = x_i * lambda_{i, S}(0)，这样 sum w_i = x
/// 这种转换使得后续的 MPC 签名可以通过简单的加法同态来完成
///
/// **流程**:
/// 1. 确定参与计算的所有节点索引集合 $S$ (`all_indices`)
/// 2. 计算当前节点的拉格朗日系数 lambda_i
/// 3. 将私钥分片 x_i 乘以 lambda_i 得到 w_i
///
/// **生产环境通信**:
/// **不涉及**。这是一个本地计算过程。只要所有参与方对“谁参与了签名 (集合 S)”达成共识，
/// 每个人就可以独立在本地完成转换，无需交换数据。
pub fn shamir_portable_to_additive_portable(
    mut share: PortableKeyShare,
    all_indices: &[u64],
) -> Result<PortableKeyShare> {
    // 1. Parse secret (Shamir share)
    let padded = pad_hex(strip_0x(&share.x_hex).to_string());
    let bytes = hex::decode(&padded)?;
    let mut s_bytes = k256::FieldBytes::default();
    if bytes.len() > 32 {
        return Err(anyhow!("Scalar bytes too long"));
    }
    let offset = 32 - bytes.len();
    s_bytes[offset..].copy_from_slice(&bytes);
    
    let secret = Option::<Scalar>::from(Scalar::from_repr(s_bytes)).context("Invalid scalar")?;

    // 2. Calculate Lagrange Coefficient
    // Note: cggmp uses 0-based index i, so x = i + 1 for polynomial evaluation
    let my_idx = share.i as u64 + 1;
    let lambda = crate::math::calculate_lagrange_coefficient(my_idx, all_indices);

    // 3. Convert to Additive Share: w_i = x_i * lambda_i
    let additive_secret = secret * lambda;

    // 4. Update share
    share.x_hex = hex::encode(additive_secret.to_bytes());
    
    // 更新阈值信息：加法分片本质上是 n-of-n，所以阈值等于总人数
    share.t = share.n;

    Ok(share)
}
