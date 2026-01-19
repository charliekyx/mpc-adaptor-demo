use crate::bridge;
use crate::eth_utils::{calc_recovery_id, compute_eth_address_from_pubkey};

use anyhow::{anyhow, Context};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::{ExecutionId, KeyShare, PregeneratedPrimes};
use rand_core::OsRng;
use round_based::sim::Simulation;
use sha2::Sha256;
use std::fs;
use std::path::Path;

pub async fn run_cggmp_signing(
    shares: &[KeyShare<cggmp24::supported_curves::Secp256k1, SecurityLevel128>],
    message_hash_bytes: [u8; 32],
) -> anyhow::Result<([u8; 32], [u8; 32], u8)> {
    type E = cggmp24::supported_curves::Secp256k1;
    let message_scalar =
        cggmp24::generic_ec::Scalar::<E>::from_be_bytes_mod_order(&message_hash_bytes);
    let prehashed_message = cggmp24::signing::PrehashedDataToSign::from_scalar(message_scalar);
    let n = shares.len();
    let participants: Vec<u16> = shares.iter().map(|s| s.core.i).collect();
    println!(
        "      [SIGN] cggmp24 signing with {} participants: {:?}",
        n, participants
    );
    let mut simulation = Simulation::empty();
    let eid = ExecutionId::new(b"initial-signing-session");

    for i in 0..n {
        let share = shares[i].clone();
        let participants = participants.clone();
        let eid = eid.clone();
        let prehashed_message = prehashed_message;
        simulation.add_async_party(move |party| async move {
            cggmp24::signing(eid, share.core.i, &participants, &share)
                .set_digest::<Sha256>()
                .sign(&mut OsRng, party, &prehashed_message)
                .await
        });
    }
    let results = simulation
        .run()
        .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
    let signature = results[0]
        .as_ref()
        .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
    let r = signature.r.to_be_bytes();
    let s = signature.s.to_be_bytes();
    let pubkey = shares[0].shared_public_key;
    let expected_addr = compute_eth_address_from_pubkey(&pubkey.to_bytes(false));
    let v = calc_recovery_id(
        &r.as_ref().try_into()?,
        &s.as_ref().try_into()?,
        &message_hash_bytes,
        expected_addr,
    )
    .map_err(|e| anyhow!(e))?;
    Ok((r.as_ref().try_into()?, s.as_ref().try_into()?, v))
}

/// 运行完整的 DKG 过程并保存结果
pub async fn run_dkg_and_save(
    execution_id: ExecutionId<'_>,
    n: u16,
    t: u16,
) -> anyhow::Result<Vec<KeyShare<cggmp24::supported_curves::Secp256k1, SecurityLevel128>>> {
    type E = cggmp24::supported_curves::Secp256k1;
    type L = SecurityLevel128;

    let primes_path = "data/primes.txt";
    let primes = if Path::new(primes_path).exists() {
        println!("      [DKG] 正在从 {} 加载预生成的素数...", primes_path);
        let content = fs::read_to_string(primes_path)?;
        serde_json::from_str::<PregeneratedPrimes<L>>(&content)
            .context("Failed to deserialize primes")?
    } else {
        println!("      [DKG] 正在预生成素数 (2048-bit RSA 较慢，请稍候)...");
        let p = PregeneratedPrimes::<L>::generate(&mut OsRng);
        fs::write(primes_path, serde_json::to_string_pretty(&p)?)?;
        p
    };

    // 1. Aux Gen
    println!("      [DKG] 阶段 1/2: 生成辅助信息 (Paillier 密钥)...");
    let mut sim_aux = Simulation::empty();
    for i in 0..n {
        let primes = primes.clone();
        sim_aux.add_async_party(move |party| async move {
            cggmp24::aux_info_gen(execution_id, i, n, primes)
                .start(&mut OsRng, party)
                .await
        });
    }
    let aux_results = sim_aux
        .run()
        .map_err(|e| anyhow!("AuxGen failed: {:?}", e))?;
    let mut aux_infos = Vec::new();
    for (i, res) in aux_results.into_iter().enumerate() {
        let aux = res.map_err(|e| anyhow!("Party {} AuxGen failed: {:?}", i, e))?;
        fs::write(
            format!("data/aux_info_party_{}.json", i),
            serde_json::to_string_pretty(&aux)?,
        )?;
        aux_infos.push(aux);
    }

    // 2. Keygen
    println!("      [DKG] 阶段 2/2: 生成私钥分片 (Secp256k1)...");
    let mut sim_keygen = Simulation::empty();
    for i in 0..n {
        sim_keygen.add_async_party(move |party| async move {
            cggmp24::keygen::<E>(execution_id, i, n)
                .set_threshold(t)
                .start(&mut OsRng, party)
                .await
        });
    }
    let keygen_results = sim_keygen
        .run()
        .map_err(|e| anyhow!("Keygen failed: {:?}", e))?;
    let mut incomplete_shares = Vec::new();
    for (i, res) in keygen_results.into_iter().enumerate() {
        let share = res.map_err(|e| anyhow!("Party {} Keygen failed: {:?}", i, e))?;
        fs::write(
            format!("data/incomplete_key_share_party_{}.json", i),
            serde_json::to_string_pretty(&share)?,
        )?;
        incomplete_shares.push(share);
    }

    // 3. Combine
    let mut complete_shares = Vec::new();
    for (i, (core, aux)) in incomplete_shares
        .into_iter()
        .zip(aux_infos.into_iter())
        .enumerate()
    {
        complete_shares.push(
            KeyShare::from_parts((core, aux))
                .map_err(|e| anyhow!("Combine failed {}: {:?}", i, e))?,
        );
    }
    Ok(complete_shares)
}

pub async fn mock_run_cggmp_dkg(
    party_id: u16,
) -> anyhow::Result<KeyShare<cggmp24::supported_curves::Secp256k1, SecurityLevel128>> {
    let core_str =
        fs::read_to_string(format!("data/incomplete_key_share_party_{}.json", party_id))?;
    let aux_str = fs::read_to_string(format!("data/aux_info_party_{}.json", party_id))?;
    let combined_json = serde_json::json!({ "core": serde_json::from_str::<serde_json::Value>(&core_str)?, "aux": serde_json::from_str::<serde_json::Value>(&aux_str)? });
    Ok(serde_json::from_value(combined_json)?)
}

/// 检查 DKG 所需的原始数据文件是否存在
fn check_dkg_files_exist(n: u16) -> bool {
    for i in 0..n {
        let core_path = format!("data/incomplete_key_share_party_{}.json", i);
        let aux_path = format!("data/aux_info_party_{}.json", i);
        if !Path::new(&core_path).exists() || !Path::new(&aux_path).exists() {
            return false;
        }
    }
    true
}

/// 获取现有的 DKG 密钥分片，如果不存在或不匹配则运行新的 DKG
pub async fn run_dkg(
    n_parties: u16,
    threshold: u16,
    execution_id: ExecutionId<'_>,
) -> anyhow::Result<Vec<KeyShare<cggmp24::supported_curves::Secp256k1, SecurityLevel128>>> {
    let mut cggmp_shares = vec![];
    let mut should_run_dkg = true;

    if check_dkg_files_exist(n_parties) {
        println!("      [INFO] 检测到现有 DKG 数据，正在加载...");
        let mut loaded_shares = vec![];
        let mut load_success = true;

        for i in 0..n_parties {
            match mock_run_cggmp_dkg(i).await {
                Ok(share) => loaded_shares.push(share),
                Err(e) => {
                    println!(
                        "      [WARN] 加载 Party {} 数据失败: {}。将重新运行 DKG。",
                        i, e
                    );
                    load_success = false;
                    break;
                }
            }
        }

        if load_success {
            if let Some(first_share) = loaded_shares.first() {
                let portable = bridge::from_cggmp_to_portable(first_share)?;
                let loaded_threshold = portable.t;
                if loaded_threshold > 0 {
                    println!(
                        "      [INFO] 已加载 DKG 数据: min_signers={}",
                        loaded_threshold
                    );

                    if loaded_threshold == threshold {
                        cggmp_shares = loaded_shares;
                        should_run_dkg = false;
                    } else {
                        println!("      [WARN] 数据文件阈值 ({}) 与代码配置 ({}) 不匹配。正在清除旧数据并重新运行 DKG...", loaded_threshold, threshold);
                        let _ = fs::remove_dir_all("data");
                        should_run_dkg = true;
                    }
                }
            }
        }
    }

    if should_run_dkg {
        println!("      [INFO] 正在启动交互式 DKG 流程...");
        fs::create_dir_all("data")?;
        cggmp_shares = run_dkg_and_save(execution_id, n_parties, threshold).await?;
    }

    if cggmp_shares.is_empty() {
        return Err(anyhow!("未加载到有效的 Key Shares,且 DKG 未运行。"));
    }

    // 这个地方确认下partyid 和 signer id的区别
    // 必须对份额按 Party ID 进行排序，确保后续协议参与方顺序一致
    cggmp_shares.sort_by_key(|s| s.core.i);
    Ok(cggmp_shares)
}
