
pub const GPG_HEADER_EXTENSION_FLAG :u8 = 0x40;
pub const GPG_EXTENSION_MASK :u8 = 0x3f;
pub const GPG_NORMAL_MASK :u8 = 0x1f;
pub const GPG_NORMAL_SHIFT :usize = 0x2;


pub const GPG_EXTHDR_LEN_MASK : u8 = 0xc0;
pub const GPG_EXTHDR_MAX_CODE : u8 = 0xff;

pub const PUBKEY_ALGO_RSA : u8 = 1;
pub const PUBKEY_ALGO_RSA_E : u8 = 2;
pub const PUBKEY_ALGO_RSA_S : u8 = 3;
pub const PUBKEY_ALGO_ELGAMAL_E :u8 = 16;
pub const PUBKEY_ALGO_DSA : u8 = 17;
pub const PUBKEY_ALGO_ECDH :u8       = 18;
pub const PUBKEY_ALGO_ECDSA :u8 = 19;
pub const PUBKEY_ALGO_ELGAMAL :u8 = 20;
pub const PUBKEY_ALGO_EDDSA :u8 = 22;
pub const PUBKEY_ALGO_PRIVATE10:u8 = 110;

pub const PKT_PUBLIC_KEY :u8 = 6;
pub const PKT_USER_ID :u8 = 13;

pub (crate) const GPG_CRC24_INIT :u32 = 0xB704CE;
pub (crate) const GPG_CRC24_POLY :u32 = 0x864CFB;
