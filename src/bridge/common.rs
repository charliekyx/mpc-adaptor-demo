// ============================================================================
// 1. 数据结构定义 (Data Structures)
// ============================================================================

/// 便携式密钥分片 (PortableKeyShare)
///
/// 这是一个中间格式，完全由 String (Hex) 组成，用于在不同 MPC 库之间传输数据，
/// 或者保存到磁盘。它剥离了具体的 Rust 类型依赖。
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct PortableKeyShare {
    pub i: u16,        // 节点索引
    pub t: u16,        // 阈值
    pub n: u16,        // 总人数
    pub x_hex: String, // 私钥分片 (Scalar)
    pub y_hex: String, // 总公钥 (Point, compressed hex)
}

// ============================================================================
// 2. Hex 字符串工具函数 (Hex Utilities)
// ============================================================================

pub fn ensure_0x(s: &str) -> String {
    if s.starts_with("0x") {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

pub fn strip_0x(s: &str) -> &str {
    s.trim_start_matches("0x")
}

pub fn pad_hex(s: String) -> String {
    if s.len() % 2 != 0 {
        format!("0{}", s)
    } else {
        s
    }
}
