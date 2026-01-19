use super::common::{
    ensure_0x, pad_hex, strip_0x, PortableKeyShare,
};
use anyhow::{anyhow, Context, Result};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, Field, Group, PrimeField};
use k256::Scalar;
use manul::protocol::PartyId;
use num_bigint::BigInt;
use num_traits::Num;
use serde::Serialize;
use synedrion::{AuxInfo, KeyShare as SynedrionKeyShare};

// ============================================================================
// Synedrion 适配器 (Synedrion Adapters)
// ============================================================================

/// 导入到 Synedrion 格式
///
/// **功能**: 将 `PortableKeyShare` 转换为 `synedrion::KeyShare`。
pub fn from_portable_to_synedrion<P: synedrion::SchemeParams>(
    portable: &PortableKeyShare,
) -> Result<SynedrionKeyShare<P, u16>>
where
    <P::Curve as CurveArithmetic>::ProjectivePoint: ToEncodedPoint<P::Curve>,
{
    // 1. 构造 KeyShare (ECDSA 部分)
    let x_bigint = BigInt::from_str_radix(&portable.x_hex, 16)?;

    let scalar = {
        // Determine the expected byte length for the scalar based on the SchemeParams P
        let mut x_bytes = [0u8; 32];
        let x_be_bytes = x_bigint.to_bytes_be().1;
        let len = x_be_bytes.len().min(32);
        x_bytes[32 - len..].copy_from_slice(&x_be_bytes[x_be_bytes.len() - len..]);

        // Use PrimeField::from_repr. Note: This assumes x_bytes is a valid canonical representation.
        let mut bytes = elliptic_curve::FieldBytes::<P::Curve>::default();
        bytes.copy_from_slice(&x_bytes);
        <P::Curve as CurveArithmetic>::Scalar::from_repr(bytes).unwrap()
    };

    let x_point = <P::Curve as CurveArithmetic>::ProjectivePoint::generator() * scalar;

    // Construct KeyShare via JSON to bypass private constructor
    let x_point_hex = hex::encode(x_point.to_encoded_point(true).as_bytes());
    let x_point_json = serde_json::Value::String(ensure_0x(&x_point_hex));

    // 构造公钥分片列表 [[id, point_hex], ...]
    let public_shares_list = serde_json::json!([[portable.i, x_point_json]]);

    let key_share_json = serde_json::json!({
        "owner": portable.i,
        "secret": ensure_0x(&portable.x_hex),
        "public": public_shares_list
    });

    let key_share: SynedrionKeyShare<P, u16> = serde_json::from_value(key_share_json)
        .context("Failed to deserialize KeyShare from JSON")?;

    Ok(key_share)
}

/// 从 Synedrion 导出
///
/// **功能**: 提取 `synedrion::KeyShare` 中的私钥和元数据。
pub fn from_synedrion_to_portable<P: synedrion::SchemeParams, Id: PartyId + Into<u16> + Copy>(
    share: &SynedrionKeyShare<P, Id>,
    y_hex: String,
) -> Result<PortableKeyShare> {
    // 1. 提取私钥分片 (此时是 Additive Share)
    let v = serde_json::to_value(share)?;
    let raw_x_hex = v
        .get("secret")
        .and_then(|s| s.as_str())
        .context("Missing secret from SynedrionKeyShare")?
        .trim_start_matches("0x")
        .to_string();
    let x_hex = pad_hex(raw_x_hex);

    // Calculate n from share's public list
    let n = v
        .get("public")
        .and_then(|l| l.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as u16;

    Ok(PortableKeyShare {
        i: (*share.owner()).into(),
        t: 0,
        n,
        x_hex,
        y_hex,
    })
}

// ============================================================================
// 核心桥接逻辑 (Core Bridge Logic: Math Transformations)
// ============================================================================

pub fn parse_point<P: synedrion::SchemeParams>(
    hex_str: &str,
) -> Result<<P::Curve as CurveArithmetic>::ProjectivePoint>
where
    <P::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<P::Curve>,
{
    let padded = pad_hex(strip_0x(hex_str).to_string());
    let bytes = hex::decode(&padded)?;
    let encoded = EncodedPoint::<P::Curve>::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("Invalid encoded point bytes: {}", e))?;
    Option::from(<P::Curve as CurveArithmetic>::ProjectivePoint::from_encoded_point(&encoded))
        .context("Failed to decode point from bytes")
}

// ============================================================================
// 辅助访问器 (Accessors & Helpers)
// ============================================================================

/// 获取特定参与方的公钥分片点
pub fn get_public_share_point<P: synedrion::SchemeParams, Id: Serialize>(
    share: &SynedrionKeyShare<P, Id>,
    party_id: Id,
) -> Result<<P::Curve as CurveArithmetic>::ProjectivePoint>
where
    Id: PartyId,
    <P::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<P::Curve>,
{
    let v = serde_json::to_value(share)?;
    // Serialize party_id to string to match JSON map keys
    let pid_val = serde_json::to_value(&party_id)?;

    let list = v
        .get("public")
        .and_then(|l| l.as_array())
        .context("No public shares")?;
    let hex_str = list
        .iter()
        .find_map(|item| {
            let pair = item.as_array()?;
            if pair.len() >= 2 && pair[0] == pid_val {
                pair[1].as_str()
            } else {
                None
            }
        })
        .context("Public share not found")?;

    parse_point::<P>(hex_str)
}

/// 获取全局公钥 (所有公钥分片之和)
pub fn get_global_public_key_point<P: synedrion::SchemeParams, Id>(
    share: &SynedrionKeyShare<P, Id>,
) -> Result<<P::Curve as CurveArithmetic>::ProjectivePoint>
where
    Id: PartyId,
    <P::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<P::Curve>,
{
    let v = serde_json::to_value(share)?;
    let list = v
        .get("public")
        .and_then(|l| l.as_array())
        .context("No public shares")?;

    // Sum all points
    let mut points = Vec::new();
    for item in list {
        let pair = item.as_array().context("Invalid pair")?;
        if pair.len() >= 2 {
            let hex_str = pair[1].as_str().context("Not a string")?;
            points.push(parse_point::<P>(hex_str)?);
        }
    }

    Ok(points.into_iter().sum())
}

/// 获取 Paillier N (从 AuxInfo 中提取)
pub fn get_aux_n_hex<P: synedrion::SchemeParams, Id: Serialize>(
    aux: &AuxInfo<P, Id>,
    party_id: Id,
) -> Result<String>
where
    Id: PartyId,
{
    let v = serde_json::to_value(aux)?;
    let pid_val = serde_json::to_value(&party_id)?;

    let list = v
        .get("public")
        .and_then(|l| l.as_array())
        .context("No public aux")?;

    let info = list
        .iter()
        .find_map(|item| {
            let pair = item.as_array()?;
            if pair.len() >= 2 && pair[0] == pid_val {
                Some(&pair[1])
            } else {
                None
            }
        })
        .context("Paillier N not found for party")?;

    let n_hex = info
        .pointer("/paillier_pk/modulus")
        .and_then(|s| s.as_str())
        .context("Paillier N not found")?
        .trim_start_matches("0x")
        .to_string();
    Ok(n_hex)
}

/// 转换 KeyShare/AuxInfo 的 ID 类型 (通过 JSON 中转)
pub fn convert_synedrion_types<P, FromId, ToId>(
    share: &SynedrionKeyShare<P, FromId>,
    aux: &AuxInfo<P, FromId>,
) -> Result<(SynedrionKeyShare<P, ToId>, AuxInfo<P, ToId>)>
where
    P: synedrion::SchemeParams,
    FromId: PartyId + 'static,
    ToId: PartyId + 'static,
{
    let share_json = serde_json::to_string(share)?;
    let aux_json = serde_json::to_string(aux)?;

    let new_share = serde_json::from_str(&share_json).context("Failed to convert KeyShare type")?;
    let new_aux = serde_json::from_str(&aux_json).context("Failed to convert AuxInfo type")?;

    Ok((new_share, new_aux))
}

/// 仅转换 KeyShare 的 ID 类型
pub fn convert_synedrion_key_share<P, FromId, ToId>(
    share: &SynedrionKeyShare<P, FromId>,
) -> Result<SynedrionKeyShare<P, ToId>>
where
    P: synedrion::SchemeParams,
    FromId: PartyId + 'static,
    ToId: PartyId + 'static,
{
    let share_json = serde_json::to_string(share)?;
    serde_json::from_str(&share_json).context("Failed to convert KeyShare type")
}

/// 从 KeyShareChange 中提取公钥增量 (Delta)
pub fn extract_refresh_delta<P, Id>(
    change: &synedrion::KeyShareChange<P, Id>,
    verifier_id: Id,
) -> Result<Option<<P::Curve as CurveArithmetic>::ProjectivePoint>>
where
    P: synedrion::SchemeParams,
    Id: PartyId,
    <P::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<P::Curve>,
{
    let share_json = serde_json::to_value(change)?;
    let v_id_val = serde_json::to_value(&verifier_id)?;

    let changes_list = share_json
        .get("public_share_changes")
        .and_then(|l| l.as_array());

    let delta_hex_opt = changes_list.and_then(|list| {
        list.iter().find_map(|item| {
            let pair = item.as_array()?;
            if pair.len() >= 2 && pair[0] == v_id_val {
                pair[1].as_str()
            } else {
                None
            }
        })
    });

    if let Some(delta_hex) = delta_hex_opt {
        let delta = parse_point::<P>(delta_hex)?;
        Ok(Some(delta))
    } else {
        Ok(None)
    }
}
