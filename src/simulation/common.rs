use serde::{Deserialize, Serialize};
use sha2::digest::Digest;
use sha3::Shake256;
use synedrion::signature::{
    self, DigestVerifier, Error as SignatureError, Keypair, RandomizedDigestSigner, Signer,
    Verifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SimpleVerifier(pub u16);

impl From<SimpleVerifier> for u16 {
    fn from(v: SimpleVerifier) -> Self {
        v.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FastSecp256k1;

impl synedrion::SchemeParams for FastSecp256k1 {
    type Curve = k256::Secp256k1;
    type Digest = Shake256;
    const SECURITY_BITS: usize = 128;
    type Paillier = synedrion::k256::PaillierProduction128;
    type ExtraWideUint = crypto_bigint::Uint<120>;
}

#[derive(Clone, Debug)]
/// [WARNING] SimpleSigner 是一个用于测试的虚拟签名者。
/// 它不执行任何加密签名，仅用于模拟网络层身份验证。
/// 在生产环境中，必须使用真实的加密签名（如 Ed25519）或 mTLS 来保护节点间的通信。
pub struct SimpleSigner {
    pub id: u16,
    pub verifier: SimpleVerifier,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DummySignature(Vec<u8>);

impl Keypair for SimpleSigner {
    type VerifyingKey = SimpleVerifier;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifier
    }
}

impl<D: Digest> RandomizedDigestSigner<D, DummySignature> for SimpleSigner {
    fn try_sign_digest_with_rng(
        &self,
        _rng: &mut (impl signature::rand_core::CryptoRng + signature::rand_core::RngCore),
        digest: D,
    ) -> Result<DummySignature, SignatureError> {
        Ok(DummySignature(digest.finalize().to_vec()))
    }
}

impl Signer<DummySignature> for SimpleSigner {
    // 这不是真正的签名，只是把消息字节包装起来
    fn try_sign(&self, msg: &[u8]) -> Result<DummySignature, SignatureError> {
        Ok(DummySignature(msg.to_vec()))
    }
}

impl<D: Digest> DigestVerifier<D, DummySignature> for SimpleVerifier {
    fn verify_digest(&self, _digest: D, _signature: &DummySignature) -> Result<(), SignatureError> {
        Ok(())
    }
}

impl Verifier<DummySignature> for SimpleVerifier {
    // 这不是真正的验证，永远返回 Ok，意味着接受任何伪造的消息
    fn verify(&self, _msg: &[u8], _signature: &DummySignature) -> Result<(), SignatureError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleSessionParams;

impl manul::session::SessionParameters for SimpleSessionParams {
    type Signer = SimpleSigner;
    type Verifier = SimpleVerifier;
    type Signature = DummySignature;
    type Digest = manul::dev::TestHasher;
    type WireFormat = manul::dev::BinaryFormat;
}

/// 辅助函数：截断长十六进制字符串用于演示
pub fn truncate_hex(hex: &str) -> String {
    if hex.len() <= 20 {
        hex.to_string()
    } else {
        format!("{}...{}", &hex[..10], &hex[hex.len() - 10..])
    }
}
