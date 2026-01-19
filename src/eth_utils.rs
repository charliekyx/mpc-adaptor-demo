use ethers::prelude::*;
use ethers::utils::keccak256;
use ethers::utils::rlp;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// 1. Compute Ethereum address from public key bytes
/// Supports both compressed (33 bytes) and uncompressed (65 bytes) formats.
pub fn compute_eth_address_from_pubkey(pubkey_bytes: &[u8]) -> Address {
    let pubkey = if pubkey_bytes.len() == 33 {
        let p = k256::PublicKey::from_sec1_bytes(pubkey_bytes).expect("Invalid compressed pubkey");
        p.to_encoded_point(false).as_bytes().to_vec()
    } else {
        pubkey_bytes.to_vec()
    };

    // Ethereum address = Keccak256(pubkey without 0x04 prefix)[last 20 bytes]
    let hash = keccak256(&pubkey[1..]);
    Address::from_slice(&hash[12..])
}

/// Helper: Create a standard transaction request
pub fn create_tx_request(
    to: Address,
    value_wei: u64,
    nonce: u64,
    chain_id: u64,
    gas_price: U256,
) -> TransactionRequest {
    TransactionRequest::new()
        .to(to)
        .value(value_wei)
        .gas(21000) // Standard transfer gas limit
        .gas_price(gas_price)
        .nonce(nonce)
        .chain_id(chain_id)
}

/// 2. Construct and sign the raw transaction
/// Returns the RLP encoded hex string ready for broadcast.
pub fn construct_and_sign_tx(
    chain_id: u64,
    nonce: u64,
    to: Address,
    value_wei: u64,
    r: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
    gas_price: U256,
) -> String {
    let tx = create_tx_request(to, value_wei, nonce, chain_id, gas_price);
    encode_signed_tx(&tx, r, s, recovery_id, chain_id)
}

/// Helper: Encode a signed transaction request to RLP hex
pub fn encode_signed_tx(
    tx: &TransactionRequest,
    r: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
    chain_id: u64,
) -> String {
    
    let mut signature = ethers::types::Signature {
        r: r.into(),
        s: s.into(),
        v: recovery_id as u64,
    };
    // 手动计算 EIP-155 标准的 v 值，否则在 Sepolia 等网络上无法通过校验
    // 公式: v = recovery_id + chain_id * 2 + 35
    signature.v = signature.v + chain_id * 2 + 35;

    // Get RLP encoded Signed Transaction
    let rlp_bytes = tx.rlp_signed(&signature);
    format!("0x{}", hex::encode(rlp_bytes))
}

/// Helper: Calculate Recovery ID (v) by checking which one recovers the expected address
pub fn calc_recovery_id(
    r: &[u8; 32],
    s: &[u8; 32],
    message_hash: &[u8; 32],
    expected_address: Address,
) -> Result<u8, String> {
    let sig_0 = ethers::types::Signature { r: U256::from_big_endian(r), s: U256::from_big_endian(s), v: 27 };
    let sig_1 = ethers::types::Signature { r: U256::from_big_endian(r), s: U256::from_big_endian(s), v: 28 };

    if let Ok(addr) = sig_0.recover(H256::from(*message_hash)) {
        if addr == expected_address { return Ok(0); }
    }
    if let Ok(addr) = sig_1.recover(H256::from(*message_hash)) {
        if addr == expected_address { return Ok(1); }
    }
    Err(format!("Could not recover expected address {:?}. Signature might be invalid.", expected_address))
}

/// 3. Broadcast the raw transaction to the network
pub async fn broadcast_tx(rpc_url: &str, raw_tx_hex: &str) -> Result<H256, String> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| format!("Failed to create provider: {}", e))?;
    
    let tx_bytes = hex::decode(raw_tx_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    let pending_tx = provider.send_raw_transaction(tx_bytes.into())
        .await
        .map_err(|e| format!("Failed to send transaction: {}", e))?;
    
    Ok(pending_tx.tx_hash())
}

/// 4. Get the current nonce for an address
pub async fn get_nonce(rpc_url: &str, address: Address) -> Result<u64, String> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| format!("Failed to create provider: {}", e))?;
    // 使用 Pending 状态获取 Nonce，以包含交易池中未打包的交易，防止 "nonce too low"
    let nonce = provider.get_transaction_count(address, Some(BlockNumber::Pending.into())).await
        .map_err(|e| format!("Failed to get nonce: {}", e))?;
    Ok(nonce.as_u64())
}

/// 5. Get current gas price
pub async fn get_gas_price(rpc_url: &str) -> Result<U256, String> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| format!("Failed to create provider: {}", e))?;
    provider.get_gas_price().await
        .map_err(|e| format!("Failed to get gas price: {}", e))
}

/// 6. Recover address from signed transaction hex (for debugging)
pub fn recover_address_from_tx(raw_tx_hex: &str) -> Result<Address, String> {
    let tx_bytes = hex::decode(raw_tx_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Hex decode error: {}", e))?;
    let (tx, sig) = TransactionRequest::decode_signed_rlp(&rlp::Rlp::new(&tx_bytes))
        .map_err(|e| format!("RLP decode error: {}", e))?;
    sig.recover(tx.sighash()).map_err(|e| format!("Recovery error: {}", e))
}

/// 7. Get current balance
pub async fn get_balance(rpc_url: &str, address: Address) -> Result<U256, String> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| format!("Failed to create provider: {}", e))?;
    provider.get_balance(address, Some(BlockNumber::Pending.into())).await
        .map_err(|e| format!("Failed to get balance: {}", e))
}