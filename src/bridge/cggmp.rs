use super::common::{pad_hex, strip_0x, PortableKeyShare};
use anyhow::{anyhow, Context, Result};
use cggmp24::generic_ec::{Point, Scalar};
use cggmp24::key_share::AnyKeyShare; // 尽管未直接使用，但保留以防 trait 依赖
use cggmp24::key_share::KeyShare as CggmpKeyShare;
use cggmp24::security_level::SecurityLevel;
use elliptic_curve::{Field, PrimeField};
use rand_core::OsRng;
use serde_json::Value;

// ============================================================================
// CGGMP24 适配器 (CGGMP Adapters)
// ============================================================================

/// 从 cggmp24 导出密钥分片
///
/// **功能**: 将 `cggmp24::KeyShare` 转换为通用的 `PortableKeyShare`。
pub fn from_cggmp_to_portable<E: cggmp24::generic_ec::Curve, L: SecurityLevel>(
    share: &CggmpKeyShare<E, L>,
) -> Result<PortableKeyShare> {
    // Use serde to bypass private field access
    let v: Value = serde_json::to_value(share)?;

    // 1. Extract core.x
    // cggmp24 serializes scalars as hex strings usually
    let raw_x_hex = v
        .pointer("/core/x")
        .and_then(|s| s.as_str())
        .context("Missing core.x")?
        .to_string();
    let x_hex = pad_hex(strip_0x(&raw_x_hex).to_string());

    // 2. Extract Public Key Y
    let y_hex = hex::encode(share.shared_public_key().to_bytes(true));

    // 3. Extract metadata
    let i = v.pointer("/core/i").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let min_signers = v
        .pointer("/core/vss_setup/min_signers")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let n = v
        .pointer("/core/vss_setup/I")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as u16;

    Ok(PortableKeyShare {
        i,
        t: min_signers,
        n,
        x_hex,
        y_hex,
    })
}

/// 更新 cggmp24 密钥分片
///
/// **功能**: 使用刷新后的数据 (PortableKeyShare) 更新旧的 cggmp24::KeyShare 模板。
pub fn from_portable_to_cggmp<E, L>(
    template_share: &CggmpKeyShare<E, L>,
    refreshed: &PortableKeyShare,
    new_public_shares: Option<&[String]>,
    new_vss_commitments: Option<&[String]>,
) -> Result<CggmpKeyShare<E, L>>
where
    E: cggmp24::generic_ec::Curve,
    L: SecurityLevel,
{
    let mut share_json = serde_json::to_value(template_share)?;

    // Update Core (x)
    if let Some(core) = share_json.get_mut("core") {
        if let Some(x_field) = core.get_mut("x") {
            *x_field = serde_json::Value::String(refreshed.x_hex.clone());
        }

        // Update Public Shares
        if let Some(ps) = new_public_shares {
            if let Some(ps_field) = core.get_mut("public_shares") {
                *ps_field = serde_json::json!(ps);
            }
        }

        // Update VSS Commitments
        if let Some(comm) = new_vss_commitments {
            if !comm.is_empty() {
                if let Some(vss) = core.get_mut("vss_setup") {
                    if let Some(comm_field) = vss.get_mut("commitments") {
                        *comm_field = serde_json::json!(comm);
                    }
                }
                // [FIX] Update shared_public_key
                // The shared public key must match the first commitment (constant term of the polynomial).
                if let Some(first_comm) = comm.first() {
                    if let Some(pk_field) = core.get_mut("shared_public_key") {
                        *pk_field = serde_json::Value::String(first_comm.clone());
                    }
                }
            }
        }
    }

    let updated_share: CggmpKeyShare<E, L> =
        serde_json::from_value(share_json).context("Failed to deserialize patched KeyShare")?;

    Ok(updated_share)
}

/// 重构全局参数 (Reconstruct Global Parameters)
///
/// **功能**: 根据一组 PortableKeyShare (Shamir 分片)，重构多项式，计算 VSS Commitments 和 Public Shares。
/// 这些参数对于所有参与方都是相同的。
///
/// **为什么需要 (Why Reconstruct)**:
/// 1. **数据一致性**: cggmp24 的 KeyShare 结构体不仅包含自己的私钥分片，还必须包含定义整个秘密多项式的
///    全局参数 (VSS Commitments) 以及其他所有人的公钥分片 (Public Shares)。
/// 2. **来源**: 当我们通过 "Bridge" 机制（例如从 Synedrion 转换而来，或外部刷新了私钥）更新了私钥分片 x 时，
///    旧的全局参数（对应旧多项式）就失效了。必须根据新的私钥分片重新计算出对应的多项式参数，否则 `KeyShare`
///    内部数据不自洽。
/// 3. **后果**: 如果不更新这些参数，在后续 MPC 签名过程中，零知识证明 (ZK Proofs) 会失败（因为证明是基于
///    Commitments 进行的），导致协议中止或被判定为恶意节点。
///
/// **通信与安全 (Communication & Security)**:
/// - **注意**: 此函数目前的实现依赖于输入一组**私钥分片** (`x_hex`)。
/// - **场景**: 这通常用于 **Trusted Dealer (可信分发者)** 模式，或者在测试/模拟环境中。
/// - **生产环境**: 在去中心化的生产环境中，任何单一方都不应拥有所有人的私钥分片。
///   在实际 MPC 协议 (如 DKG/Resharing) 中，各方会交互**公钥分片**或**Commitments**，
///   而不是汇聚私钥来计算。此函数相当于模拟了 DKG 结束时各方达成共识的全局参数。
///
/// todo:
// 目前的实现中，CGGMP 部分是通过私钥重算公钥，而 Synedrion 是通过协议输出公钥。
// 未来优化时，
// 可以让 CGGMP 的更新逻辑直接使用 Synedrion 产出的公钥列表，从而避免重复计算和对私钥的依赖。
pub fn reconstruct_global_params<E: cggmp24::generic_ec::Curve>(
    refreshed_data: &[PortableKeyShare],
) -> Result<(Vec<String>, Vec<String>)> {
    // 1. 重构多项式系数 (Reconstruct Polynomial Coefficients)
    let mut shares_points = Vec::new();
    for data in refreshed_data {
        let x_bytes = hex::decode(&data.x_hex)?;
        let x_scalar = Scalar::<E>::from_be_bytes_mod_order(&x_bytes);
        // x coordinate for party i is i+1 (cggmp convention)
        let x_coord = Scalar::<E>::from(data.i as u64 + 1);
        let y_point = Point::<E>::generator() * x_scalar;
        shares_points.push((x_coord, y_point));
    }

    let n_shares = shares_points.len();
    if n_shares == 0 {
        return Err(anyhow!("No refreshed data provided"));
    }
    let required_min_signers = refreshed_data[0].t as usize;
    if n_shares < required_min_signers {
        return Err(anyhow!(
            "参与方不足以重构多项式: 需要 {}, 实际 {}",
            required_min_signers,
            n_shares
        ));
    }

    // Lagrange Interpolation to find coefficients
    let zero_point = Point::<E>::generator() * Scalar::<E>::from(0u64);
    let mut coeffs = vec![zero_point; n_shares];

    for i in 0..n_shares {
        let (xi, yi) = shares_points[i];
        let mut denom = Scalar::<E>::from(1u64);
        for j in 0..n_shares {
            if i == j {
                continue;
            }
            let (xj, _) = shares_points[j];
            denom = denom * (xi - xj);
        }
        let inv_denom = denom.invert().ok_or(anyhow!("Inversion failed"))?;

        let mut poly = vec![Scalar::<E>::from(0u64); n_shares];
        poly[0] = Scalar::<E>::from(1u64);

        for j in 0..n_shares {
            if i == j {
                continue;
            }
            let (xj, _) = shares_points[j];
            for k in (1..n_shares).rev() {
                poly[k] = poly[k - 1] - xj * poly[k];
            }
            poly[0] = -xj * poly[0];
        }

        for k in 0..n_shares {
            coeffs[k] = coeffs[k] + yi * (poly[k] * inv_denom);
        }
    }

    let new_commitments_hex: Vec<String> = coeffs
        .iter()
        .map(|c| hex::encode(c.to_bytes(true)))
        .collect();

    // 2. 计算所有人的 Public Shares
    let n_total = refreshed_data.first().map(|d| d.n).unwrap_or(0) as usize;
    let mut new_public_shares_hex = Vec::with_capacity(n_total);

    for i in 0..n_total {
        let x_coord = Scalar::<E>::from((i + 1) as u64);
        let mut y_point = Point::<E>::generator() * Scalar::<E>::from(0u64);
        let mut x_pow = Scalar::<E>::one();
        for coeff in &coeffs {
            y_point = y_point + *coeff * x_pow;
            x_pow = x_pow * x_coord;
        }
        new_public_shares_hex.push(hex::encode(y_point.to_bytes(true)));
    }

    Ok((new_commitments_hex, new_public_shares_hex))
}

/// 批量更新 cggmp24 密钥分片 (Batch Update)
/// **功能**: 根据一组新的 PortableKeyShare (Shamir 分片)，重构多项式，计算全局参数 (VSS Commitments, Public Shares)，
/// 并更新所有的 cggmp24 KeyShare。
pub fn update_cggmp_shares_from_portable<E, L>(
    old_shares_templates: &[CggmpKeyShare<E, L>],
    refreshed_data: &[PortableKeyShare],
) -> Result<Vec<CggmpKeyShare<E, L>>>
where
    E: cggmp24::generic_ec::Curve,
    L: SecurityLevel,
{
    let (new_commitments_hex, new_public_shares_hex) =
        reconstruct_global_params::<E>(refreshed_data)?;

    let mut updated_cggmp_shares = Vec::new();
    // Create a map for refreshed data to match by ID
    let refreshed_map: std::collections::HashMap<u16, &PortableKeyShare> =
        refreshed_data.iter().map(|s| (s.i, s)).collect();

    for template_share in old_shares_templates {
        let party_id = template_share.core.i;
        if let Some(refreshed) = refreshed_map.get(&party_id) {
            let updated_share = from_portable_to_cggmp(
                template_share,
                refreshed,
                Some(&new_public_shares_hex),
                Some(&new_commitments_hex),
            )?;
            updated_cggmp_shares.push(updated_share);
        } else {
            return Err(anyhow!("Missing refreshed data for party {}", party_id));
        }
    }

    Ok(updated_cggmp_shares)
}
