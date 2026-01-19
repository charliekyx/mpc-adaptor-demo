mod bridge;
mod eth_utils;
mod math;
mod simulation;

use crate::bridge::get_global_public_key_point;
use crate::eth_utils::{
    broadcast_tx, compute_eth_address_from_pubkey, create_tx_request, encode_signed_tx,
    get_balance, get_gas_price, get_nonce,
};
use crate::simulation::{
    run_cggmp_signing, run_synedrion_signing_simulation, truncate_hex, FastSecp256k1,
    SimpleVerifier,
};
use anyhow::Context;
use cggmp24::ExecutionId;
use ethers::types::U256;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::collections::{BTreeMap, BTreeSet};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";
    let to_address =
        "0x945ffa853f241ee857353cf4ffce0c338377e5d3".parse::<ethers::types::Address>()?;
    let chain_id = 11155111; // Sepolia
    let _gas_limit = 21000u64;

    println!("=== 开始混合 MPC 协议 & Sepolia 交易演示 ===");

    // ========================================================================
    // 阶段 1: cggmp24 Distributed Key Generation (DKG)
    // ========================================================================
    println!("[1/3] setup");
    println!("[1.1] 运行 cggmp24 DKG ...");

    let n_parties = 5;
    let threshold = 3;
    let min_signers = threshold;
    let execution_id = ExecutionId::new(b"demo-mixed-mpc-session");

    let cggmp_shares = simulation::run_dkg(n_parties, threshold, execution_id).await?;

    // [验证] 计算原始地址
    let pubkey_bytes = cggmp_shares[0].shared_public_key.to_bytes(true);
    let my_address = eth_utils::compute_eth_address_from_pubkey(&pubkey_bytes);

    println!(
        "      [GLOBAL] 共享公钥 (Y): 0x{}",
        truncate_hex(&hex::encode(&pubkey_bytes))
    );
    println!("      钱包地址 (由 DKG 生成): {:?}", my_address);
    let initial_balance = eth_utils::get_balance(rpc_url, my_address)
        .await
        .unwrap_or(U256::zero());
    println!("      初始余额: {} wei", initial_balance);

    println!(
        "      DKG 完成。加载了 {} 方的数据，阈值为 {}",
        n_parties, threshold
    );

    let signing_len = min_signers as usize;

    // ========================================================================
    // 阶段 1.5: 初始交易验证 (cggmp24)
    // ========================================================================
    println!("[1.2] 验证初始 DKG 密钥交易能力 (cggmp24 版本)...");

    let gas_price = eth_utils::get_gas_price(rpc_url)
        .await
        .unwrap_or(U256::from(1_000_000_000));

    let nonce_initial = eth_utils::get_nonce(rpc_url, my_address).await.unwrap_or(0);

    // 构造交易 (Value = 50 wei)
    let tx_req_initial =
        eth_utils::create_tx_request(to_address, 50, nonce_initial, chain_id, gas_price);
    let tx_hash_initial = tx_req_initial.sighash();

    let signing_shares = &cggmp_shares[0..signing_len];
    let (r_init, s_init, v_init) =
        simulation::run_cggmp_signing(signing_shares, tx_hash_initial.into()).await?;
    let raw_tx_hex_initial = eth_utils::construct_and_sign_tx(
        chain_id,
        nonce_initial,
        to_address,
        50,
        r_init,
        s_init,
        v_init,
        gas_price,
    );

    match eth_utils::broadcast_tx(rpc_url, &raw_tx_hex_initial).await {
        Ok(h) => println!("      CGGMP24 初始交易已广播! Hash: {:?}", h),
        Err(e) => println!("      [ERROR] CGGMP24 初始交易广播失败: {}", e),
    }

    // ========================================================================
    // 阶段 2: 数据桥接 (Bridge cggmp24 -> synedrion)
    // ========================================================================
    println!("[2/4] 第一轮数据转换 cggmp24 -> synedrion ...");

    let cache_path = "data/refreshed_synedrion_shares.json";
    let force_refresh = false; // 如果需要强制重新生成，改为 true

    type SynedrionParams = FastSecp256k1;

    let all_party_indices: Vec<u64> = cggmp_shares.iter().map(|s| s.core.i as u64 + 1).collect();

    // 运行 Synedrion 原生的 AuxGen 协议生成辅助信息 (Paillier 密钥等)
    let party_ids_set: BTreeSet<u16> = cggmp_shares.iter().map(|s| s.core.i).collect();
    let synedrion_aux_map =
        simulation::run_synedrion_aux_gen::<SynedrionParams>(party_ids_set).await?;

    let mut synedrion_data = vec![];
    for share in &cggmp_shares {
        // cggmp24 -> portable -> additive portable -> synedrion
        let portable_data = bridge::cggmp::from_cggmp_to_portable(share)?;
        // [FIX] 不要在这里转换为 5-of-5 加法分片，保持 Shamir 形式以支持后续的 t-of-n 签名

        let synedrion_share =
            bridge::synedrion::from_portable_to_synedrion::<SynedrionParams>(&portable_data)?;

        let synedrion_aux = synedrion_aux_map
            .get(&share.core.i)
            .cloned()
            .context("Missing generated AuxInfo for party")?;

        println!("        成功映射到 Synedrion 结构体:");

        let pk_share_point =
            bridge::get_public_share_point(&synedrion_share, share.core.i).unwrap();
        let pk_share_hex = hex::encode(pk_share_point.to_encoded_point(true).as_bytes());

        println!(
            "          - [KeyShare] Owner: {}, 公钥分片: 0x{}",
            synedrion_share.owner(),
            truncate_hex(&pk_share_hex)
        );

        // Use bridge helper to get N
        let paillier_n = bridge::get_aux_n_hex(&synedrion_aux, share.core.i)
            .unwrap_or_else(|_| "N/A".to_string());

        println!(
            "          - [AuxInfo] Paillier N: {}",
            truncate_hex(&paillier_n)
        );

        synedrion_data.push((synedrion_share, synedrion_aux));
    }

    println!("      所有参与方数据转换成功！");

    // todo: 这是一轮通信，可以避免吗？
    let mut all_public_shares_map = BTreeMap::new();
    for (s, _) in &synedrion_data {
        let pt = bridge::get_public_share_point(s, *s.owner()).expect("Missing public share");
        all_public_shares_map.insert(s.owner().to_string(), pt);
    }
    for (share, _) in &mut synedrion_data {
        let mut v = serde_json::to_value(&*share)?;
        let mut new_list = Vec::new();
        for (k_str, pt) in &all_public_shares_map {
            let k_u64: u64 = k_str.parse().unwrap();
            let hex_val = format!("0x{}", hex::encode(pt.to_encoded_point(true).as_bytes()));
            new_list.push(serde_json::json!([k_u64, hex_val]));
        }
        v["public"] = serde_json::Value::Array(new_list);
        *share = serde_json::from_value(v)?;
    }

    // [验证] 验证 Bridge 转换后的 Synedrion 地址 (必须在聚合公钥分片后进行)
    if let Some((first_syn_share, _)) = synedrion_data.first() {
        let global_pk = get_global_public_key_point(first_syn_share)?;
        let pk_bytes = global_pk.to_encoded_point(true).as_bytes().to_vec();
        let addr = compute_eth_address_from_pubkey(&pk_bytes);
        println!("      [CHECK] Bridge 转换后 (Synedrion) 地址: {:?}", addr);
        if addr != my_address {
            println!("      [WARN] 地址不匹配!");
        }
    }

    let global_y_hex = hex::encode(&pubkey_bytes);

    println!("\n[3/4] 运行 Synedrion Key Refresh (模拟)...");

    let updated_shares = crate::simulation::run_refresh_workflow(
        synedrion_data.clone(),
        min_signers as u16,
        cache_path,
        force_refresh,
    )
    .await?;

    // [验证] 验证 Refresh 后的地址
    if let Some((_, (share, _))) = updated_shares.iter().next() {
        let global_pk = get_global_public_key_point(share)?;
        let pk_bytes = global_pk.to_encoded_point(true).as_bytes().to_vec();
        let addr = compute_eth_address_from_pubkey(&pk_bytes);
        println!("      [CHECK] Key Refresh 后 (Synedrion) 地址: {:?}", addr);
    }
    
    // ========================================================================
    // 阶段 4: [核心演示] 使用刷新后的私钥签名交易
    // ========================================================================
    println!("\n[4/4] 验证交易能力 (Sepolia)...");

    let mut nonce = get_nonce(rpc_url, my_address).await.unwrap_or(0);
    if nonce <= nonce_initial {
        nonce = nonce_initial + 1;
    }
    let gas_price = get_gas_price(rpc_url)
        .await
        .unwrap_or(U256::from(1_000_000_000));
    let tx_req = create_tx_request(to_address, 100, nonce, chain_id, gas_price);
    let tx_hash = tx_req.sighash();

    // [FIX] 动态选取 3 个参与方，并进行 Shamir -> Additive (3-of-3) 转换
    // 这样 Synedrion 就会认为这是一个完整的 3-of-3 签名组，从而成功签名
    let signing_subset_keys: Vec<SimpleVerifier> = updated_shares
        .keys()
        .take(min_signers as usize)
        .cloned()
        .collect();
    let signing_indices: Vec<u64> = signing_subset_keys.iter().map(|k| k.0 as u64 + 1).collect();

    let mut signing_subset = BTreeMap::new();
    for key in &signing_subset_keys {
        let (share, aux) = updated_shares.get(key).unwrap();
        
        // 1. 导出 Shamir 分片
        let mut portable = bridge::synedrion::from_synedrion_to_portable(share, global_y_hex.clone())?;
        // 2. 针对当前选取的 3 人子集，计算拉格朗日系数，转换为加法分片
        portable = bridge::core::shamir_portable_to_additive_portable(portable, &signing_indices)?;
        // 3. 导入回 Synedrion 格式用于签名
        let additive_share = bridge::synedrion::from_portable_to_synedrion::<SynedrionParams>(&portable)?;
        
        signing_subset.insert(*key, (additive_share, aux.clone()));
    }

    println!("      [INFO] 选取 {} 个参与方进行签名: {:?}", signing_subset.len(), signing_subset.keys());

    let (r, s, rec_id) =
        run_synedrion_signing_simulation::<SynedrionParams>(&signing_subset, tx_hash.into())
            .await?;
    println!("      Synedrion MPC 签名生成成功!");

    let raw_tx_hex = encode_signed_tx(&tx_req, r, s, rec_id, chain_id);
    match broadcast_tx(rpc_url, &raw_tx_hex).await {
        Ok(tx_hash) => println!("[4.1] Synedrion 交易已成功广播! Hash: {:?}", tx_hash),
        Err(e) => println!(
            "      [ERROR] 广播失败: {} (提示：请检查地址余额或 Nonce 是否正确)",
            e
        ),
    }

    // 构造第二个交易
    println!("      [INFO] 等待 5 秒以确保 Nonce 同步...");
    sleep(Duration::from_secs(5)).await;
    let current_nonce = get_nonce(rpc_url, my_address).await.unwrap_or(nonce + 1);
    let nonce_2 = if current_nonce <= nonce {
        nonce + 1
    } else {
        current_nonce
    };
    let gas_price_2 = get_gas_price(rpc_url).await.unwrap_or(gas_price);
    let _balance_check = get_balance(rpc_url, my_address)
        .await
        .unwrap_or(U256::zero());
    let tx_req_2 = create_tx_request(to_address, 200, nonce_2, chain_id, gas_price_2);
    let tx_hash_2 = tx_req_2.sighash();

    println!("      [BRIDGE] 第二轮数据转换 synedrion -> cggmp24...");

    // Synedrion -> portable -> cggmp24 (直接导出，因为已经是 Shamir 格式)
    let mut refreshed_cggmp_portable = Vec::new();
    for (share, _) in updated_shares.values() {
        let mut portable = bridge::synedrion::from_synedrion_to_portable(share, global_y_hex.clone())?;
        portable.t = min_signers as u16; // 恢复阈值信息
        refreshed_cggmp_portable.push(portable);
    }

    if let Some(share) = refreshed_cggmp_portable.first() {
        let y_bytes = hex::decode(&share.y_hex)?;
        let addr = compute_eth_address_from_pubkey(&y_bytes);
        println!(
            "      [CHECK] 逆向 Bridge 后 (CGGMP Portable) 地址: {:?}",
            addr
        );
        if addr != my_address {
            println!("      [WARN] 地址不匹配!");
        }
    }

    let signing_shares_templates = &cggmp_shares[0..signing_len];
    let signing_portable = &refreshed_cggmp_portable[0..signing_len];

    let updated_cggmp_shares =
        bridge::update_cggmp_shares_from_portable(signing_shares_templates, signing_portable)?;

    let (r2, s2, rec_id2) = run_cggmp_signing(&updated_cggmp_shares, tx_hash_2.into()).await?;
    let raw_tx_hex_2 = encode_signed_tx(&tx_req_2, r2, s2, rec_id2, chain_id);

    println!("      CGGMP24 MPC 签名生成成功!");

    match broadcast_tx(rpc_url, &raw_tx_hex_2).await {
        Ok(h) => println!("[4.2] key refreshed cggmp24 交易已广播! Hash: {:?}", h),
        Err(e) => println!(
            "      [ERROR] 广播失败: {} (提示：请检查地址余额或 Nonce 是否正确)",
            e
        ),
    }

    println!("\n === 成功! Key Refresh & MPC签名 & 交易 完成 ===");

    Ok(())
}
